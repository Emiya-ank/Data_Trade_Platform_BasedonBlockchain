package communication

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeJoinRejectsTraversal(t *testing.T) {
	_, err := safeJoin("./data", "../escape", "proof.bin")
	if err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
}

func TestSafeJoinBuildsPath(t *testing.T) {
	path, err := safeJoin("./data", "order-1", "proof.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "data\\order-1\\proof.bin"
	if path != want {
		t.Fatalf("unexpected path: got %q want %q", path, want)
	}
}

func TestTradeHandlerListsOrderFiles(t *testing.T) {
	baseDir := t.TempDir()
	orderDir := filepath.Join(baseDir, "order-1")
	if err := os.MkdirAll(orderDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(orderDir, "a.bin"), []byte("a"), 0644); err != nil {
		t.Fatalf("write file a failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(orderDir, "b.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("write file b failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/trade/order-1", nil)
	rr := httptest.NewRecorder()
	NewSellerMux(baseDir).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d", rr.Code)
	}

	var files []string
	if err := json.Unmarshal(rr.Body.Bytes(), &files); err != nil {
		t.Fatalf("decode file list failed: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("unexpected file count: got %d", len(files))
	}
}
