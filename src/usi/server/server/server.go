// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/server/server/server.go
package pubkeydir

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	store    Store
	verifier Verifier
}

func NewServer(store Store, verifier Verifier) *Server {
	log.Printf("[INFO] Server: creating new server instance")
	return &Server{store: store, verifier: verifier}
}

func (s *Server) Handler() http.Handler {
	log.Printf("[INFO] Handler: initializing HTTP handlers")
	mux := http.NewServeMux()

	mux.HandleFunc("POST /bundles", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[INFO] Server: POST /bundles request received from %s", r.RemoteAddr)
		start := time.Now()
		s.createBundle(w, r)
		log.Printf("[INFO] Server: POST /bundles completed in %v", time.Since(start))
	})

	mux.HandleFunc("GET /bundles", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[INFO] Server: GET /bundles request received from %s", r.RemoteAddr)
		start := time.Now()
		s.listBundles(w, r)
		log.Printf("[INFO] Server: GET /bundles completed in %v", time.Since(start))
	})

	mux.HandleFunc("GET /bundles/{fingerprint}", func(w http.ResponseWriter, r *http.Request) {
		fp := r.PathValue("fingerprint")
		fpShort := fp
		if len(fpShort) > 16 {
			fpShort = fpShort[:16] + "..."
		}
		log.Printf("[INFO] Server: GET /bundles/%s request received from %s", fpShort, r.RemoteAddr)
		start := time.Now()
		s.getBundle(w, r)
		log.Printf("[INFO] Server: GET /bundles/%s completed in %v", fpShort, time.Since(start))
	})

	mux.HandleFunc("POST /bundles/{fingerprint}/revoke", func(w http.ResponseWriter, r *http.Request) {
		fp := r.PathValue("fingerprint")
		fpShort := fp
		if len(fpShort) > 16 {
			fpShort = fpShort[:16] + "..."
		}
		log.Printf("[INFO] Server: POST /bundles/%s/revoke request received from %s", fpShort, r.RemoteAddr)
		start := time.Now()
		s.revokeBundle(w, r)
		log.Printf("[INFO] Server: POST /bundles/%s/revoke completed in %v", fpShort, time.Since(start))
	})

	log.Printf("[SUCCESS] Handler: HTTP handlers registered")
	return mux
}

func (s *Server) createBundle(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] createBundle: processing bundle registration")

	var bundle PublicKeyBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		log.Printf("[ERROR] createBundle: failed to decode bundle: %v", err)
		writeError(w, http.StatusBadRequest, err)
		return
	}

	fpShort := bundle.Fingerprint
	if len(fpShort) > 16 {
		fpShort = fpShort[:16] + "..."
	}

	log.Printf("[INFO] createBundle: bundle details - fingerprint: %s, org: %s, label: %s", fpShort, bundle.Organization, bundle.Label)
	log.Printf("[DEBUG] createBundle: signature algorithm: %s, KEM algorithm: %s", bundle.SignatureAlgorithm, bundle.KEMAlgorithm)
	log.Printf("[DEBUG] createBundle: signature public key size: %d bytes, KEM public key size: %d bytes",
		len(bundle.SignaturePublicKey), len(bundle.KEMPublicKey))
	log.Printf("[DEBUG] createBundle: status: %s, created at: %v", bundle.Status, bundle.CreatedAt)

	log.Printf("[INFO] createBundle: validating bundle")
	if err := ValidateBundle(bundle, s.verifier); err != nil {
		log.Printf("[ERROR] createBundle: bundle validation failed: %v", err)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	log.Printf("[SUCCESS] createBundle: bundle validation passed")

	log.Printf("[INFO] createBundle: storing bundle in database")
	if err := s.store.Put(bundle); err != nil {
		log.Printf("[ERROR] createBundle: store put failed: %v", err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	log.Printf("[SUCCESS] createBundle: bundle stored successfully")

	log.Printf("[SUCCESS] createBundle: bundle registered successfully for org: %s (fingerprint: %s)", bundle.Organization, fpShort)
	writeJSON(w, http.StatusCreated, bundle)
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.PathValue("fingerprint")
	fpShort := fingerprint
	if len(fpShort) > 16 {
		fpShort = fpShort[:16] + "..."
	}

	log.Printf("[INFO] getBundle: looking up bundle for fingerprint: %s", fpShort)

	bundle, err := s.store.Get(fingerprint)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			log.Printf("[INFO] getBundle: bundle not found for fingerprint: %s", fpShort)
			writeError(w, http.StatusNotFound, err)
			return
		}
		if errors.Is(err, ErrInvalidFingerprint) {
			log.Printf("[WARN] getBundle: invalid fingerprint format: %s", fpShort)
			writeError(w, http.StatusNotFound, err)
			return
		}
		log.Printf("[ERROR] getBundle: database error for fingerprint %s: %v", fpShort, err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	log.Printf("[SUCCESS] getBundle: bundle found for fingerprint: %s", fpShort)
	log.Printf("[DEBUG] getBundle: org: %s, label: %s, status: %s", bundle.Organization, bundle.Label, bundle.Status)
	log.Printf("[DEBUG] getBundle: created at: %s, updated at: %s", bundle.CreatedAt.Format(time.RFC3339), bundle.UpdatedAt.Format(time.RFC3339))
	log.Printf("[DEBUG] getBundle: signature public key size: %d bytes, KEM public key size: %d bytes",
		len(bundle.SignaturePublicKey), len(bundle.KEMPublicKey))

	if bundle.Status == StatusRevoked {
		log.Printf("[WARN] getBundle: bundle is revoked for fingerprint: %s", fpShort)
		log.Printf("[DEBUG] getBundle: revoked at: %s, reason: %s",
			bundle.RevokedAt.Format(time.RFC3339), bundle.RevocationReason)
	}

	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) listBundles(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] listBundles: retrieving all bundles from store")

	bundles, err := s.store.List()
	if err != nil {
		log.Printf("[ERROR] listBundles: failed to list bundles: %v", err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	log.Printf("[SUCCESS] listBundles: retrieved %d bundles", len(bundles))

	// Log summary of all bundles
	if len(bundles) > 0 {
		log.Printf("[INFO] listBundles: bundle summary:")
		activeCount := 0
		revokedCount := 0

		for i, b := range bundles {
			fpShort := b.Fingerprint
			if len(fpShort) > 16 {
				fpShort = fpShort[:16] + "..."
			}

			if b.Status == StatusRevoked {
				revokedCount++
				log.Printf("[DEBUG] listBundles: bundle %d - [REVOKED] org: %s, fp: %s", i+1, b.Organization, fpShort)
			} else {
				activeCount++
				log.Printf("[DEBUG] listBundles: bundle %d - [ACTIVE] org: %s, fp: %s", i+1, b.Organization, fpShort)
			}
		}
		log.Printf("[INFO] listBundles: summary - %d active, %d revoked", activeCount, revokedCount)
	} else {
		log.Printf("[INFO] listBundles: no bundles registered in store")
	}

	writeJSON(w, http.StatusOK, bundles)
}

func (s *Server) revokeBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[WARN] revokeBundle: failed to decode reason (using empty string): %v", err)
		req.Reason = ""
	}
	log.Printf("[INFO] revokeBundle: revocation reason: %s", req.Reason)

	fingerprint := r.PathValue("fingerprint")
	fpShort := fingerprint
	if len(fpShort) > 16 {
		fpShort = fpShort[:16] + "..."
	}

	log.Printf("[INFO] revokeBundle: revoking bundle for fingerprint: %s", fpShort)

	if err := s.store.Revoke(fingerprint, strings.TrimSpace(req.Reason)); err != nil {
		if errors.Is(err, ErrNotFound) {
			log.Printf("[WARN] revokeBundle: bundle not found for fingerprint: %s", fpShort)
			writeError(w, http.StatusNotFound, err)
			return
		}
		if errors.Is(err, ErrInvalidFingerprint) {
			log.Printf("[WARN] revokeBundle: invalid fingerprint format: %s", fpShort)
			writeError(w, http.StatusNotFound, err)
			return
		}
		log.Printf("[ERROR] revokeBundle: revoke failed for fingerprint %s: %v", fpShort, err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	log.Printf("[SUCCESS] revokeBundle: bundle revoked successfully for fingerprint: %s", fpShort)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	log.Printf("[DEBUG] writeJSON: writing JSON response with status %d", status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("[ERROR] writeJSON: failed to encode JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	log.Printf("[DEBUG] writeError: writing error response: status=%d, error=%v", status, err)
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
