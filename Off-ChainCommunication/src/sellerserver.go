package communication

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func safeJoin(base, orderID, filename string) (string, error) {
	cleanOrder := filepath.Clean(orderID)
	cleanFile := filepath.Clean(filename)

	if strings.Contains(cleanOrder, "..") || strings.Contains(cleanFile, "..") {
		return "", fmt.Errorf("invalid path")
	}

	return filepath.Join(base, cleanOrder, cleanFile), nil
}

func safeOrderDir(base, orderID string) (string, error) {
	cleanOrder := filepath.Clean(orderID)
	if strings.Contains(cleanOrder, "..") {
		return "", fmt.Errorf("invalid path")
	}
	return filepath.Join(base, cleanOrder), nil
}

func listOrderFiles(baseDir, orderID string) ([]string, error) {
	orderDir, err := safeOrderDir(baseDir, orderID)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(orderDir)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	return files, nil
}

func TradeHandler(baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/trade/"), "/")
		if trimmed == "" {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}

		parts := strings.Split(trimmed, "/")
		if len(parts) == 1 {
			orderID := parts[0]
			files, err := listOrderFiles(baseDir, orderID)
			if err != nil {
				if os.IsNotExist(err) {
					http.Error(w, "order not found", http.StatusNotFound)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(files); err != nil {
				http.Error(w, "failed to encode file list", http.StatusInternalServerError)
				return
			}
			return
		}

		if len(parts) != 2 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}

		orderID := parts[0]
		filename := parts[1]

		path, err := safeJoin(baseDir, orderID, filename)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if _, err := os.Stat(path); os.IsNotExist(err) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		switch {
		case strings.HasSuffix(filename, ".json"):
			w.Header().Set("Content-Type", "application/json")
		case strings.HasSuffix(filename, ".bin"):
			w.Header().Set("Content-Type", "application/octet-stream")
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		http.ServeFile(w, r, path)
	}
}

func NewSellerMux(baseDir string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/trade/", TradeHandler(baseDir))
	return mux
}

func RunSellerServer(addr, baseDir string) error {
	return http.ListenAndServe(addr, NewSellerMux(baseDir))
}
