package communication

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func downloadFile(url string, outputPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func listTradeFiles(baseURL, orderID string) ([]string, error) {
	listURL := fmt.Sprintf("%s/trade/%s", strings.TrimRight(baseURL, "/"), url.PathEscape(orderID))
	resp, err := http.Get(listURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list files failed: %s", resp.Status)
	}

	var files []string
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	return files, nil
}

func isSafeFilename(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return filepath.Base(name) == name
}

func DownloadTrade(baseURL string, orderID string, saveDir string) error {
	dir := filepath.Join(saveDir, orderID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	files, err := listTradeFiles(baseURL, orderID)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return fmt.Errorf("no files found for order %s", orderID)
	}

	for _, file := range files {
		if !isSafeFilename(file) {
			return fmt.Errorf("unsafe filename from server: %s", file)
		}

		url := fmt.Sprintf(
			"%s/trade/%s/%s",
			strings.TrimRight(baseURL, "/"),
			url.PathEscape(orderID),
			url.PathEscape(file),
		)
		outPath := filepath.Join(dir, file)

		fmt.Println("Downloading:", url)

		if err := downloadFile(url, outPath); err != nil {
			return fmt.Errorf("failed to download %s: %w", file, err)
		}
	}

	fmt.Println("All files downloaded to:", dir)
	return nil
}
