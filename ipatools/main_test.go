package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeIPA(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	w, err := zw.Create("Payload/Test.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("plist"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectIPA(t *testing.T) {
	path := makeIPA(t)
	r, err := inspectIPA(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Entries != 1 || len(r.AppRoots) != 1 || r.SHA256 == "" {
		t.Fatalf("unexpected inspection: %+v", r)
	}
}

func TestToZipDoesNotOverwrite(t *testing.T) {
	path := makeIPA(t)
	destination := filepath.Join(filepath.Dir(path), "sample.zip")
	if _, err := toZipCommand([]string{"--input", path, "--output", destination}); err != nil {
		t.Fatal(err)
	}
	if _, err := toZipCommand([]string{"--input", path, "--output", destination}); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestDownloadRequiresAuthorizationBeforeExecution(t *testing.T) {
	_, err := downloadCommand([]string{"--app-id", "632064380", "--output", filepath.Join(t.TempDir(), "app.ipa")})
	if err == nil || !strings.Contains(err.Error(), "--authorized") {
		t.Fatalf("expected authorization failure, got %v", err)
	}
}

func TestDownloadRejectsNonNumericAppID(t *testing.T) {
	_, err := downloadCommand([]string{"--app-id", "../../bad", "--output", filepath.Join(t.TempDir(), "app.ipa"), "--authorized"})
	if err == nil || !strings.Contains(err.Error(), "numeric") {
		t.Fatalf("expected numeric validation failure, got %v", err)
	}
}
