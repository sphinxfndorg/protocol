// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/vault/helper.go
package vault

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
)

// Constants
// Constants for manifest versions
const (
	ManifestVersionV1 = 1 // Original version (passphrase-based)
	ManifestVersionV2 = 2 // Simple recipient list (still passphrase-based)
	ManifestVersionV3 = 3 // Hybrid KEM (X25519 + Kyber768)
)

// ---------------------------------------------------------------------
// Public GUI wrappers
// ---------------------------------------------------------------------
// PerformEncryptionSilent performs encryption without showing dialogs
func PerformEncryptionSilent(folder, passphrase string, recipientFingerprints ...string) error {
	log.Printf("[INFO] PerformEncryptionSilent: starting silent encryption for folder: %s", folder)
	log.Printf("[DEBUG] PerformEncryptionSilent: passphrase length: %d, recipients: %d", len(passphrase), len(recipientFingerprints))

	err := EncryptFolder(folder, passphrase, recipientFingerprints...)
	if err != nil {
		log.Printf("[ERROR] PerformEncryptionSilent: encryption failed: %v", err)
	} else {
		log.Printf("[SUCCESS] PerformEncryptionSilent: encryption completed successfully for folder: %s", folder)
	}
	return err
}

// PerformEncryption encrypts a folder and shows GUI dialogs for success or error
func PerformEncryption(folder, passphrase string, w fyne.Window, recipientFingerprints ...string) {
	log.Printf("[INFO] PerformEncryption: starting encryption for folder: %s", folder)
	log.Printf("[DEBUG] PerformEncryption: passphrase length: %d, recipients: %d", len(passphrase), len(recipientFingerprints))

	if err := EncryptFolder(folder, passphrase, recipientFingerprints...); err != nil {
		log.Printf("[ERROR] PerformEncryption: encryption failed: %v", err)
		fyne.Do(func() {
			dialog.ShowError(err, w)
		})
	} else {
		log.Printf("[SUCCESS] PerformEncryption: encryption completed successfully for folder: %s", folder)
		fyne.Do(func() {
			dialog.ShowInformation("Locked", fmt.Sprintf(
				"Folder is now a locked file:\n%s.vault\n\nDouble-click will show \"cannot open\".\nUse USI → Select Vault File → Decrypt to restore.", filepath.Base(folder)), w)
		})
	}
}

// ---------------------------------------------------------------------
// Helper: build manifest
// ---------------------------------------------------------------------
// buildManifest creates a manifest of files in the folder
func buildManifest(folder string) (*manifest, error) {
	log.Printf("[INFO] buildManifest: building manifest for folder: %s", folder)

	var entries []fileEntry
	fileCount := 0

	err := filepath.Walk(folder, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[ERROR] buildManifest: error walking path %s: %v", p, err)
			return err
		}

		// Skip ignored files
		if shouldIgnoreFile(p, fi) {
			log.Printf("[DEBUG] buildManifest: skipping ignored file: %s", p)
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if fi.IsDir() || strings.HasSuffix(p, vaultExt) || filepath.Base(p) == manifestFile {
			log.Printf("[DEBUG] buildManifest: skipping directory/system file: %s", p)
			return nil
		}

		fileCount++
		log.Printf("[DEBUG] buildManifest: processing file #%d: %s (size: %d bytes)", fileCount, p, fi.Size())

		rel, err := filepath.Rel(folder, p)
		if err != nil {
			log.Printf("[ERROR] buildManifest: failed to get relative path for %s: %v", p, err)
			return err
		}
		log.Printf("[DEBUG] buildManifest: relative path: %s", rel)

		log.Printf("[DEBUG] buildManifest: computing hash for: %s", p)
		h, err := blake3File(p)
		if err != nil {
			log.Printf("[ERROR] buildManifest: error hashing file %s: %v", p, err)
			return err
		}
		log.Printf("[DEBUG] buildManifest: file hash computed for %s: %x", p, h[:8])

		entries = append(entries, fileEntry{
			Path:     sanitizeFilename(rel), // Sanitize the path
			Size:     fi.Size(),
			ModTime:  fi.ModTime().UTC().Format(time.RFC3339),
			FileHash: h,
		})
		log.Printf("[DEBUG] buildManifest: file entry added to manifest: %s (hash: %x...)", rel, h[:8])
		return nil
	})

	if err != nil {
		log.Printf("[ERROR] buildManifest: error building manifest: %v", err)
		return nil, err
	}

	log.Printf("[INFO] buildManifest: collected %d manifest entries", len(entries))

	m := &manifest{
		Files:        entries,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		OriginalName: filepath.Base(folder),
	}

	log.Printf("[SUCCESS] buildManifest: manifest created successfully with timestamp: %s", m.Timestamp)
	log.Printf("[DEBUG] buildManifest: original folder name: %s", m.OriginalName)
	return m, nil
}

// isMacOSJunk returns true for macOS-injected files that must be excluded
// from the archive. Keeping them causes Finder error -36 on extraction.
//
//   - __MACOSX/   — resource fork container directory added by macOS tar
//   - ._*         — AppleDouble resource-fork sidecar files
//   - .DS_Store   — Finder metadata; irrelevant and sometimes unreadable cross-fs
func isMacOSJunk(name string) bool {
	base := filepath.Base(name)
	result := strings.HasPrefix(base, "._") ||
		base == ".DS_Store" ||
		strings.HasPrefix(filepath.ToSlash(name), "__MACOSX/") ||
		strings.Contains(filepath.ToSlash(name), "/__MACOSX/")

	if result {
		log.Printf("[DEBUG] isMacOSJunk: identified macOS junk file: %s", name)
	}
	return result
}

// tarFolder creates a gzip-compressed tar archive of folderPath into dst.
func tarFolder(folderPath string, dst io.Writer) error {
	log.Printf("[INFO] tarFolder: starting tar operation for folder: %s", folderPath)

	gw := gzip.NewWriter(dst)
	defer func() {
		if err := gw.Close(); err != nil {
			log.Printf("[ERROR] tarFolder: failed to close gzip writer: %v", err)
		} else {
			log.Printf("[DEBUG] tarFolder: gzip writer closed")
		}
	}()
	log.Printf("[DEBUG] tarFolder: gzip writer initialized")

	tw := tar.NewWriter(gw)
	defer func() {
		if err := tw.Close(); err != nil {
			log.Printf("[ERROR] tarFolder: failed to close tar writer: %v", err)
		} else {
			log.Printf("[DEBUG] tarFolder: tar writer closed")
		}
	}()
	log.Printf("[DEBUG] tarFolder: tar writer initialized")

	fileCount := 0
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[ERROR] tarFolder: walk error at %s: %v", path, err)
			return err
		}

		// Skip the root folder itself - we don't want to include it as an entry
		if path == folderPath {
			log.Printf("[DEBUG] tarFolder: skipping root folder: %s", path)
			return nil
		}

		// Derive the in-archive name relative to the folder path
		// This creates paths like "Screen Recording.mov" instead of "cuy/Screen Recording.mov"
		relPath, err := filepath.Rel(folderPath, path)
		if err != nil {
			log.Printf("[ERROR] tarFolder: failed to compute relative path for %s: %v", path, err)
			return fmt.Errorf("failed to compute relative path: %w", err)
		}
		relPath = filepath.ToSlash(relPath)

		// Skip macOS junk files
		if isMacOSJunk(relPath) {
			log.Printf("[DEBUG] tarFolder: skipping macOS junk file: %s", relPath)
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks
		if info.Mode()&os.ModeSymlink != 0 {
			log.Printf("[DEBUG] tarFolder: skipping symlink: %s", relPath)
			return nil
		}

		fileCount++
		log.Printf("[DEBUG] tarFolder: processing file #%d for tar: %s -> %s (size: %d bytes)", fileCount, path, relPath, info.Size())

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			log.Printf("[ERROR] tarFolder: failed to create tar header for %s: %v", path, err)
			return fmt.Errorf("failed to create tar header for %s: %w", path, err)
		}
		hdr.Name = relPath

		// Normalise permissions
		if info.IsDir() {
			hdr.Mode = 0755
			log.Printf("[DEBUG] tarFolder: directory header created for: %s (mode: %o)", relPath, hdr.Mode)
		} else {
			hdr.Mode = 0644
			log.Printf("[DEBUG] tarFolder: file header created for: %s (mode: %o)", relPath, hdr.Mode)
		}

		log.Printf("[DEBUG] tarFolder: writing tar header for: %s", relPath)
		if err := tw.WriteHeader(hdr); err != nil {
			log.Printf("[ERROR] tarFolder: failed to write tar header: %v", err)
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		if !info.IsDir() {
			log.Printf("[DEBUG] tarFolder: copying file content to tar: %s", path)
			f, err := os.Open(path)
			if err != nil {
				log.Printf("[ERROR] tarFolder: failed to open file: %v", err)
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					log.Printf("[ERROR] tarFolder: failed to close file: %v", err)
				}
			}()

			bytesWritten, err := io.Copy(tw, f)
			if err != nil {
				log.Printf("[ERROR] tarFolder: failed to copy file content: %v", err)
				return fmt.Errorf("failed to copy file content: %w", err)
			}
			log.Printf("[DEBUG] tarFolder: file content copied successfully for %s (bytes: %d)", relPath, bytesWritten)
		}
		return nil
	})

	if err != nil {
		log.Printf("[ERROR] tarFolder: tar walk error: %v", err)
		return fmt.Errorf("tar walk error: %w", err)
	}

	log.Printf("[SUCCESS] tarFolder: tar operation completed successfully for %s (%d files)", folderPath, fileCount)
	return nil
}

// fixFilePermissions recursively fixes permissions on all files and directories
func fixFilePermissions(dir string) error {
	log.Printf("[INFO] fixFilePermissions: fixing permissions for directory: %s", dir)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[ERROR] fixFilePermissions: walk error at %s: %v", path, err)
			return err
		}
		if info.IsDir() {
			if err := os.Chmod(path, 0755); err != nil {
				log.Printf("[WARN] fixFilePermissions: failed to chmod dir %s: %v", path, err)
			} else {
				log.Printf("[DEBUG] fixFilePermissions: set directory permissions for: %s (mode: 0755)", path)
			}
		} else {
			if err := os.Chmod(path, 0644); err != nil {
				log.Printf("[WARN] fixFilePermissions: failed to chmod file %s: %v", path, err)
			} else {
				log.Printf("[DEBUG] fixFilePermissions: set file permissions for: %s (mode: 0644)", path)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("[ERROR] fixFilePermissions: error fixing permissions: %v", err)
	} else {
		log.Printf("[SUCCESS] fixFilePermissions: permissions fixed for directory: %s", dir)
	}
	return err
}

// fixFinderAttributes removes macOS extended attributes that cause Finder error -36
func fixFinderAttributes(dir string) error {
	log.Printf("[INFO] fixFinderAttributes: removing extended attributes for: %s", dir)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[ERROR] fixFinderAttributes: walk error at %s: %v", path, err)
			return err
		}
		// Use xattr command to remove all extended attributes recursively
		cmd := exec.Command("xattr", "-cr", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[WARN] fixFinderAttributes: xattr -cr failed for %s: %v, output: %s", path, err, output)
		} else {
			log.Printf("[DEBUG] fixFinderAttributes: removed extended attributes for: %s", path)
		}
		return nil
	})

	if err != nil {
		log.Printf("[ERROR] fixFinderAttributes: error removing attributes: %v", err)
	} else {
		log.Printf("[SUCCESS] fixFinderAttributes: extended attributes removed for: %s", dir)
	}
	return err
}

// safeUntar extracts a tar.gz archive safely into destDir.
func safeUntar(tarPath, destDir string) error {
	log.Printf("[INFO] safeUntar: starting extraction of %s to %s", tarPath, destDir)

	file, err := os.Open(tarPath)
	if err != nil {
		log.Printf("[ERROR] safeUntar: failed to open tar file: %v", err)
		return fmt.Errorf("failed to open tar file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("[ERROR] safeUntar: failed to close tar file: %v", err)
		}
	}()

	destDir, err = filepath.Abs(destDir)
	if err != nil {
		log.Printf("[ERROR] safeUntar: failed to resolve destination: %v", err)
		return fmt.Errorf("failed to resolve destination: %w", err)
	}
	log.Printf("[DEBUG] safeUntar: absolute destination path: %s", destDir)

	// Ensure destination directory exists with proper permissions
	if err := os.MkdirAll(destDir, 0755); err != nil {
		log.Printf("[ERROR] safeUntar: failed to create destination directory: %v", err)
		return fmt.Errorf("failed to create destination directory: %w", err)
	}
	log.Printf("[DEBUG] safeUntar: destination directory created/verified")

	gr, err := gzip.NewReader(file)
	if err != nil {
		log.Printf("[ERROR] safeUntar: failed to create gzip reader: %v", err)
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gr.Close(); err != nil {
			log.Printf("[ERROR] safeUntar: failed to close gzip reader: %v", err)
		}
	}()
	log.Printf("[DEBUG] safeUntar: gzip reader created")

	tr := tar.NewReader(gr)
	log.Printf("[DEBUG] safeUntar: tar reader created")

	fileCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			log.Printf("[DEBUG] safeUntar: reached end of tar archive")
			break
		}
		if err != nil {
			log.Printf("[ERROR] safeUntar: tar read error: %v", err)
			return fmt.Errorf("tar read error: %w", err)
		}

		// Discard macOS resource-fork entries before touching the fs.
		if isMacOSJunk(header.Name) {
			log.Printf("[DEBUG] safeUntar: skipping macOS junk entry: %s", header.Name)
			continue
		}

		target := filepath.Join(destDir, header.Name)
		target, err = filepath.Abs(target)
		if err != nil {
			log.Printf("[ERROR] safeUntar: failed to resolve target: %v", err)
			return fmt.Errorf("failed to resolve target: %w", err)
		}

		relPath, err := filepath.Rel(destDir, target)
		if err != nil || strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
			log.Printf("[ERROR] safeUntar: path traversal detected: %s", header.Name)
			return fmt.Errorf("path traversal detected: %s", header.Name)
		}

		fileCount++
		log.Printf("[DEBUG] safeUntar: extracting #%d: %s -> %s (type: %c, size: %d bytes)",
			fileCount, header.Name, target, header.Typeflag, header.Size)

		switch header.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			log.Printf("[ERROR] safeUntar: symlinks and hard links are not allowed: %s", header.Name)
			return fmt.Errorf("symlinks and hard links are not allowed")

		case tar.TypeDir:
			// Use 0755 so Finder and other processes can traverse the dir.
			if err := os.MkdirAll(target, 0755); err != nil {
				log.Printf("[ERROR] safeUntar: failed to create directory: %v", err)
				return fmt.Errorf("failed to create directory: %w", err)
			}
			log.Printf("[DEBUG] safeUntar: directory created: %s", target)

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				log.Printf("[ERROR] safeUntar: failed to create parent directory: %v", err)
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			const maxFileSize = 1 << 30 // 1 GB
			if header.Size > maxFileSize {
				log.Printf("[ERROR] safeUntar: file too large: %s (size: %d > %d)", header.Name, header.Size, maxFileSize)
				return fmt.Errorf("file too large: %s", header.Name)
			}

			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				log.Printf("[ERROR] safeUntar: failed to create file: %v", err)
				return fmt.Errorf("failed to create file: %w", err)
			}

			written, err := io.Copy(outFile, io.LimitReader(tr, maxFileSize))
			if err != nil {
				outFile.Close()
				log.Printf("[ERROR] safeUntar: failed to write file: %v", err)
				return fmt.Errorf("failed to write file: %w", err)
			}
			if written != header.Size {
				outFile.Close()
				log.Printf("[ERROR] safeUntar: file size mismatch: %s (expected %d, got %d)", header.Name, header.Size, written)
				return fmt.Errorf("file size mismatch: %s", header.Name)
			}

			if err := outFile.Sync(); err != nil {
				outFile.Close()
				log.Printf("[ERROR] safeUntar: failed to sync file: %v", err)
				return fmt.Errorf("failed to sync file: %w", err)
			}
			outFile.Close()
			log.Printf("[DEBUG] safeUntar: file written: %s (bytes: %d)", target, written)

			if err := os.Chmod(target, 0644); err != nil {
				log.Printf("[WARN] safeUntar: failed to set file permissions: %v", err)
			} else {
				log.Printf("[DEBUG] safeUntar: file permissions set for: %s", target)
			}

			// AFTER file is written, rename it to remove problematic characters
			if newPath, err := sanitizeActualFile(target); err != nil {
				log.Printf("[WARN] safeUntar: failed to sanitize filename: %v", err)
			} else if newPath != target {
				log.Printf("[DEBUG] safeUntar: file renamed from %s to %s", filepath.Base(target), filepath.Base(newPath))
			}
		}
	}

	log.Printf("[SUCCESS] safeUntar: extraction completed successfully for %s (%d files extracted)", tarPath, fileCount)
	return nil
}

// shouldIgnoreFile checks if a file should be excluded from encryption
func shouldIgnoreFile(path string, info os.FileInfo) bool {
	filename := filepath.Base(path)
	ignored := false

	// macOS system files
	if filename == ".DS_Store" {
		log.Printf("[DEBUG] shouldIgnoreFile: ignoring .DS_Store: %s", path)
		return true
	}
	if filename == ".localized" {
		log.Printf("[DEBUG] shouldIgnoreFile: ignoring .localized: %s", path)
		return true
	}
	if strings.HasPrefix(filename, "._") { // AppleDouble resource forks
		log.Printf("[DEBUG] shouldIgnoreFile: ignoring AppleDouble file: %s", path)
		return true
	}

	// Temporary files
	if strings.HasSuffix(filename, ".tmp") || strings.HasSuffix(filename, ".temp") {
		log.Printf("[DEBUG] shouldIgnoreFile: ignoring temp file: %s", path)
		return true
	}

	// Your app's temporary message file - DO NOT SKIP!
	if filename == ".encrypted_message.txt" {
		log.Printf("[DEBUG] shouldIgnoreFile: preserving message file: %s", path)
		return false // ← Include in encryption
	}

	// Windows system files
	if filename == "Thumbs.db" || filename == "desktop.ini" {
		log.Printf("[DEBUG] shouldIgnoreFile: ignoring Windows system file: %s", path)
		return true
	}

	if ignored {
		log.Printf("[DEBUG] shouldIgnoreFile: file allowed: %s", path)
	}
	return false
}

// removeHiddenFiles removes all hidden files (starting with dot) from directory
// EXCEPT for .encrypted_message.txt which contains the embedded message
func removeHiddenFiles(dir string) error {
	log.Printf("[INFO] removeHiddenFiles: removing hidden files from: %s", dir)

	removedCount := 0
	err := filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[ERROR] removeHiddenFiles: walk error at %s: %v", path, err)
			return err
		}
		// Get the base name
		baseName := filepath.Base(path)
		// Skip the root directory itself
		if path == dir {
			log.Printf("[DEBUG] removeHiddenFiles: skipping root directory: %s", path)
			return nil
		}
		// If it starts with dot, remove it (but preserve .encrypted_message.txt)
		if strings.HasPrefix(baseName, ".") && baseName != ".encrypted_message.txt" {
			removedCount++
			log.Printf("[DEBUG] removeHiddenFiles: removing hidden file/dir: %s", path)
			if err := os.RemoveAll(path); err != nil {
				log.Printf("[WARN] removeHiddenFiles: failed to remove %s: %v", path, err)
			} else {
				log.Printf("[DEBUG] removeHiddenFiles: successfully removed: %s", path)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("[ERROR] removeHiddenFiles: error removing hidden files: %v", err)
	} else {
		log.Printf("[SUCCESS] removeHiddenFiles: removed %d hidden files/directories from: %s", removedCount, dir)
	}
	return err
}

// sanitizeFilename removes characters that cause issues on external drives
func sanitizeFilename(name string) string {
	original := name
	// Replace problematic characters
	replacer := strings.NewReplacer(
		":", "_",
		"?", "_",
		"*", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\\", "_",
		"/", "_",
	)
	result := replacer.Replace(name)

	if original != result {
		log.Printf("[DEBUG] sanitizeFilename: sanitized filename from '%s' to '%s'", original, result)
	}
	return result
}

// sanitizeActualFile renames a file to remove problematic characters
func sanitizeActualFile(oldPath string) (string, error) {
	dir := filepath.Dir(oldPath)
	oldName := filepath.Base(oldPath)

	// Replace problematic characters
	newName := strings.ReplaceAll(oldName, ":", "_")
	newName = strings.ReplaceAll(newName, "?", "_")
	newName = strings.ReplaceAll(newName, "*", "_")
	newName = strings.ReplaceAll(newName, "\"", "_")
	newName = strings.ReplaceAll(newName, "<", "_")
	newName = strings.ReplaceAll(newName, ">", "_")
	newName = strings.ReplaceAll(newName, "|", "_")

	if newName == oldName {
		log.Printf("[DEBUG] sanitizeActualFile: no sanitization needed for: %s", oldName)
		return oldPath, nil
	}

	newPath := filepath.Join(dir, newName)
	log.Printf("[DEBUG] sanitizeActualFile: renaming from '%s' to '%s'", oldName, newName)

	if err := os.Rename(oldPath, newPath); err != nil {
		log.Printf("[ERROR] sanitizeActualFile: rename failed: %v", err)
		return oldPath, err
	}

	log.Printf("[SUCCESS] sanitizeActualFile: renamed: %s -> %s", oldName, newName)
	return newPath, nil
}
