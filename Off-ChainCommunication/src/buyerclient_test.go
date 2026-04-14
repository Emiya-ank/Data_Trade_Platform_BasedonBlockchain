package communication

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadTradeDownloadsAllListedFiles(t *testing.T) {
	baseDir := t.TempDir()
	orderDir := filepath.Join(baseDir, "order-demo")
	if err := os.MkdirAll(orderDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(orderDir, "x.bin"), []byte("x"), 0644); err != nil {
		t.Fatalf("write x.bin failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(orderDir, "y.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("write y.json failed: %v", err)
	}

	server := httptest.NewServer(NewSellerMux(baseDir))
	defer server.Close()

	saveDir := t.TempDir()
	if err := DownloadTrade(server.URL, "order-demo", saveDir); err != nil {
		t.Fatalf("DownloadTrade failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(saveDir, "order-demo", "x.bin")); err != nil {
		t.Fatalf("x.bin not downloaded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(saveDir, "order-demo", "y.json")); err != nil {
		t.Fatalf("y.json not downloaded: %v", err)
	}
}

func TestIsSafeFilename(t *testing.T) {
	if isSafeFilename("../escape") {
		t.Fatal("expected traversal filename to be unsafe")
	}
	if !isSafeFilename("proof.bin") {
		t.Fatal("expected normal filename to be safe")
	}
}
