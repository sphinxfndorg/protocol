// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/kem.go
package security

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	// DefaultHandshakeTimeout bounds the whole handshake.
	DefaultHandshakeTimeout = 15 * time.Second

	kemLabel     = "sphinx-handshake-v2"
	maxAuthProof = 128 << 10 // SPHINCS+ signature + public key fit comfortably
)

// warnUnauthOnce makes the "no peer authentication" warning appear once per
// process instead of on every connection.
var warnUnauthOnce sync.Once

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// transcriptHash binds every public value exchanged, so the derived keys only
// match if both sides saw exactly the same handshake.
func transcriptHash(initX, respX, kyPub, kyCT []byte) []byte {
	h := sha3.New256()
	put := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		h.Write(l[:])
		h.Write(b)
	}
	put([]byte(kemLabel))
	put(initX)
	put(respX)
	put(kyPub)
	put(kyCT)
	return h.Sum(nil)
}

// roleDigest is what each side signs; including the role stops a proof from
// being reflected back to its author.
func roleDigest(transcript []byte, role string) []byte {
	h := sha3.New256()
	h.Write([]byte(kemLabel + "-auth|"))
	h.Write(transcript)
	h.Write([]byte(role))
	return h.Sum(nil)
}

// PerformKEM runs the hybrid X25519 + Kyber768 exchange WITHOUT peer
// authentication (see PerformKEMWithAuth).
func PerformKEM(conn net.Conn, isInitiator bool) (*EncryptionKey, error) {
	return PerformKEMWithAuth(conn, isInitiator, nil, DefaultHandshakeTimeout)
}

// PerformKEMWithAuth performs the hybrid key exchange, derives independent
// per-direction keys with HKDF bound to the transcript, and (if auth != nil)
// authenticates the peer over the encrypted channel.
func PerformKEMWithAuth(conn net.Conn, isInitiator bool, auth Authenticator, timeout time.Duration) (*EncryptionKey, error) {
	if conn == nil {
		return nil, errors.New("connection is nil")
	}
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	// A silent or slow peer must not hold this goroutine forever.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	// ----------- X25519 -----------
	xPriv := make([]byte, 32)
	if _, err := rand.Read(xPriv); err != nil {
		return nil, err
	}
	defer wipe(xPriv)

	xPub, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	peerXPub := make([]byte, 32)
	if isInitiator {
		if _, err := conn.Write(xPub); err != nil {
			return nil, fmt.Errorf("send x25519 key: %w", err)
		}
		if _, err := io.ReadFull(conn, peerXPub); err != nil {
			return nil, fmt.Errorf("read x25519 key: %w", err)
		}
	} else {
		if _, err := io.ReadFull(conn, peerXPub); err != nil {
			return nil, fmt.Errorf("read x25519 key: %w", err)
		}
		if _, err := conn.Write(xPub); err != nil {
			return nil, fmt.Errorf("send x25519 key: %w", err)
		}
	}
	// X25519 returns an error for low-order peer points (all-zero output).
	xShared, err := curve25519.X25519(xPriv, peerXPub)
	if err != nil {
		return nil, err
	}
	defer wipe(xShared)

	initX, respX := xPub, peerXPub
	if !isInitiator {
		initX, respX = peerXPub, xPub
	}

	// ----------- Kyber768 -----------
	scheme := kyber768.Scheme()
	var kemShared, kyPub, kyCT []byte

	if isInitiator {
		kyPub = make([]byte, scheme.PublicKeySize())
		if _, err := io.ReadFull(conn, kyPub); err != nil {
			return nil, fmt.Errorf("read kyber public key: %w", err)
		}
		peerPub, err := scheme.UnmarshalBinaryPublicKey(kyPub)
		if err != nil {
			return nil, err
		}
		ct, shared, err := scheme.Encapsulate(peerPub)
		if err != nil {
			return nil, err
		}
		kyCT, kemShared = ct, shared
		if _, err := conn.Write(kyCT); err != nil {
			return nil, fmt.Errorf("send kyber ciphertext: %w", err)
		}
	} else {
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		kyPub, err = pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write(kyPub); err != nil {
			return nil, fmt.Errorf("send kyber public key: %w", err)
		}
		kyCT = make([]byte, scheme.CiphertextSize())
		if _, err := io.ReadFull(conn, kyCT); err != nil {
			return nil, fmt.Errorf("read kyber ciphertext: %w", err)
		}
		kemShared, err = scheme.Decapsulate(priv, kyCT)
		if err != nil {
			return nil, err
		}
	}
	defer wipe(kemShared)

	// ----------- Key derivation -----------
	transcript := transcriptHash(initX, respX, kyPub, kyCT)

	ikm := make([]byte, 0, len(xShared)+len(kemShared))
	ikm = append(ikm, xShared...)
	ikm = append(ikm, kemShared...)
	defer wipe(ikm)

	r := hkdf.New(sha512.New, ikm, transcript, []byte(kemLabel+"|session-keys"))
	i2r, r2i := make([]byte, 32), make([]byte, 32)
	defer wipe(i2r)
	defer wipe(r2i)
	if _, err := io.ReadFull(r, i2r); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, r2i); err != nil {
		return nil, err
	}

	sendKey, recvKey := i2r, r2i
	if !isInitiator {
		sendKey, recvKey = r2i, i2r
	}
	enc, err := newDirectionalKey(sendKey, recvKey)
	if err != nil {
		return nil, err
	}

	// ----------- Peer authentication (over the encrypted channel) -----------
	if auth != nil {
		if err := authenticatePeer(conn, enc, auth, transcript, isInitiator); err != nil {
			enc.Close()
			return nil, fmt.Errorf("peer authentication failed: %w", err)
		}
		enc.PeerAuthenticated = true
	} else {
		warnUnauthOnce.Do(func() {
			log.Printf("WARNING: handshakes run WITHOUT peer authentication (vulnerable to man-in-the-middle); set Handshake.Auth (see SphincsAuthenticator)")
		})
	}
	return enc, nil
}

func writeFrame(conn net.Conn, b []byte) error {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	if _, err := conn.Write(l[:]); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

func readFrame(conn net.Conn, max int) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if int(n) > max || n == 0 {
		return nil, errors.New("invalid frame length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(conn, b); err != nil {
		return nil, err
	}
	return b, nil
}

func authenticatePeer(conn net.Conn, enc *EncryptionKey, auth Authenticator, transcript []byte, isInitiator bool) error {
	myRole, peerRole := "responder", "initiator"
	if isInitiator {
		myRole, peerRole = "initiator", "responder"
	}

	send := func() error {
		proof, err := auth.Prove(roleDigest(transcript, myRole))
		if err != nil {
			return fmt.Errorf("create proof: %w", err)
		}
		if len(proof) == 0 || len(proof) > maxAuthProof {
			return errors.New("invalid proof size")
		}
		blob, err := enc.Encrypt(proof)
		if err != nil {
			return err
		}
		return writeFrame(conn, blob)
	}
	recv := func() error {
		blob, err := readFrame(conn, maxAuthProof+64)
		if err != nil {
			return err
		}
		proof, err := enc.Decrypt(blob)
		if err != nil {
			return err
		}
		return auth.Verify(roleDigest(transcript, peerRole), proof)
	}

	if isInitiator {
		if err := send(); err != nil {
			return err
		}
		return recv()
	}
	if err := recv(); err != nil {
		return err
	}
	return send()
}
