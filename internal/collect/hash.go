package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// hashFiles computes the SHA-256 of each path and returns a lower-cased
// path -> hex-digest map. Unreadable files (locked system images, missing
// paths) are simply omitted rather than treated as errors.
func hashFiles(paths []string) map[string]string {
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if h, err := sha256File(p); err == nil {
			out[strings.ToLower(p)] = h
		}
	}
	return out
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
