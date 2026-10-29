package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const version = "1.0.0"

type result struct {
	OK          bool     `json:"ok"`
	Command     string   `json:"command"`
	Message     string   `json:"message,omitempty"`
	Error       string   `json:"error,omitempty"`
	IpatoolPath string   `json:"ipatool_path,omitempty"`
	Version     string   `json:"version,omitempty"`
	Output      string   `json:"output,omitempty"`
	ZipOutput   string   `json:"zip_output,omitempty"`
	Size        int64    `json:"size_bytes,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	Entries     int      `json:"zip_entries,omitempty"`
	AppRoots    []string `json:"app_roots,omitempty"`
	Log         string   `json:"log,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var r result
	var err error
	switch os.Args[1] {
	case "status":
		r, err = statusCommand(os.Args[2:])
	case "download":
		r, err = downloadCommand(os.Args[2:])
	case "inspect":
		r, err = inspectCommand(os.Args[2:])
	case "to-zip":
		r, err = toZipCommand(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("ipatools", version)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		r.OK = false
		r.Error = err.Error()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r)
	if err != nil {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `ipatools - safe IPA acquisition helper for authorized mobile testing

Commands:
  status
  download --bundle-id ID|--app-id ID --output FILE.ipa --authorized [--zip]
  inspect --input FILE.ipa
  to-zip --input FILE.ipa [--output FILE.zip]

Authentication is intentionally not accepted by this wrapper. Run
"ipatool auth login" interactively first; credentials stay in ipatool's
keychain/session storage.`)
}

func upstreamPath() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("IPATOOL_BIN")); configured != "" {
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", err
		}
		info, err := os.Stat(absolute)
		if err != nil || info.IsDir() {
			return "", errors.New("IPATOOL_BIN does not point to an executable file")
		}
		return absolute, nil
	}
	if self, err := os.Executable(); err == nil {
		name := "ipatool"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		sibling := filepath.Join(filepath.Dir(self), name)
		if info, statErr := os.Stat(sibling); statErr == nil && !info.IsDir() {
			return sibling, nil
		}
	}
	return exec.LookPath("ipatool")
}

func statusCommand(args []string) (result, error) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return result{Command: "status"}, err
	}
	path, err := upstreamPath()
	if err != nil {
		return result{Command: "status", Version: version, Message: "Install majd/ipatool and authenticate interactively first."}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, cmdErr := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if ctx.Err() != nil {
		return result{Command: "status", IpatoolPath: path, Version: version}, errors.New("ipatool version check timed out")
	}
	if cmdErr != nil {
		return result{Command: "status", IpatoolPath: path, Version: version, Log: limited(out)}, errors.New("ipatool executable check failed")
	}
	return result{OK: true, Command: "status", IpatoolPath: path, Version: strings.TrimSpace(string(out)), Message: "Run 'ipatool auth login' in a private terminal before downloading."}, nil
}

func downloadCommand(args []string) (result, error) {
	fs := flag.NewFlagSet("download", flag.ContinueOnError)
	bundleID := fs.String("bundle-id", "", "App Store bundle identifier")
	appID := fs.String("app-id", "", "numeric App Store application ID")
	output := fs.String("output", "", "destination .ipa file")
	makeZip := fs.Bool("zip", false, "also copy the IPA archive to .zip")
	authorized := fs.Bool("authorized", false, "confirm authorization and account rights")
	if err := fs.Parse(args); err != nil {
		return result{Command: "download"}, err
	}
	if !*authorized {
		return result{Command: "download"}, errors.New("--authorized is required; only acquire apps your account may lawfully download and you may assess")
	}
	if (*bundleID == "") == (*appID == "") {
		return result{Command: "download"}, errors.New("provide exactly one of --bundle-id or --app-id")
	}
	if *appID != "" && strings.Trim(*appID, "0123456789") != "" {
		return result{Command: "download"}, errors.New("--app-id must be numeric")
	}
	if strings.TrimSpace(*output) == "" || strings.ToLower(filepath.Ext(*output)) != ".ipa" {
		return result{Command: "download"}, errors.New("--output must end in .ipa")
	}
	absOutput, err := filepath.Abs(*output)
	if err != nil {
		return result{Command: "download"}, err
	}
	if _, err := os.Stat(absOutput); err == nil {
		return result{Command: "download"}, errors.New("refusing to overwrite an existing output file")
	}
	if err := os.MkdirAll(filepath.Dir(absOutput), 0o750); err != nil {
		return result{Command: "download"}, err
	}
	path, err := upstreamPath()
	if err != nil {
		return result{Command: "download"}, errors.New("majd/ipatool is not installed or IPATOOL_BIN is invalid")
	}
	upstreamArgs := []string{"--non-interactive", "download"}
	if *bundleID != "" {
		upstreamArgs = append(upstreamArgs, "--bundle-identifier", *bundleID)
	} else {
		upstreamArgs = append(upstreamArgs, "--app-id", *appID)
	}
	upstreamArgs = append(upstreamArgs, "--output", absOutput)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, upstreamArgs...)
	cmd.Stdin = nil
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Run(); err != nil {
		_ = os.Remove(absOutput)
		if ctx.Err() != nil {
			return result{Command: "download", Log: limited(logs.Bytes())}, errors.New("download timed out")
		}
		return result{Command: "download", Log: limited(logs.Bytes())}, fmt.Errorf("ipatool download failed: %w", err)
	}
	inspection, err := inspectIPA(absOutput)
	if err != nil {
		_ = os.Remove(absOutput)
		return result{Command: "download", Log: limited(logs.Bytes())}, fmt.Errorf("downloaded file failed IPA validation: %w", err)
	}
	inspection.OK = true
	inspection.Command = "download"
	inspection.Output = absOutput
	inspection.Log = limited(logs.Bytes())
	if *makeZip {
		zipOutput := strings.TrimSuffix(absOutput, filepath.Ext(absOutput)) + ".zip"
		if err := copyExclusive(absOutput, zipOutput); err != nil {
			return inspection, err
		}
		inspection.ZipOutput = zipOutput
	}
	return inspection, nil
}

func inspectCommand(args []string) (result, error) {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	input := fs.String("input", "", "input IPA")
	if err := fs.Parse(args); err != nil {
		return result{Command: "inspect"}, err
	}
	r, err := inspectIPA(*input)
	r.Command = "inspect"
	r.OK = err == nil
	return r, err
}

func inspectIPA(input string) (result, error) {
	absInput, err := filepath.Abs(input)
	if err != nil {
		return result{}, err
	}
	file, err := os.Open(absInput)
	if err != nil {
		return result{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		return result{}, errors.New("input is not a regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result{}, err
	}
	zr, err := zip.OpenReader(absInput)
	if err != nil {
		return result{}, fmt.Errorf("not a valid ZIP/IPA: %w", err)
	}
	defer zr.Close()
	roots := map[string]bool{}
	hasPlist := false
	for _, entry := range zr.File {
		name := filepath.ToSlash(entry.Name)
		parts := strings.Split(name, "/")
		if len(parts) >= 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			roots[parts[0]+"/"+parts[1]] = true
			if len(parts) == 3 && parts[2] == "Info.plist" {
				hasPlist = true
			}
		}
	}
	if len(roots) == 0 || !hasPlist {
		return result{}, errors.New("archive is missing Payload/*.app/Info.plist")
	}
	appRoots := make([]string, 0, len(roots))
	for root := range roots {
		appRoots = append(appRoots, root)
	}
	return result{Output: absInput, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), Entries: len(zr.File), AppRoots: appRoots}, nil
}

func toZipCommand(args []string) (result, error) {
	fs := flag.NewFlagSet("to-zip", flag.ContinueOnError)
	input := fs.String("input", "", "input IPA")
	output := fs.String("output", "", "destination ZIP")
	if err := fs.Parse(args); err != nil {
		return result{Command: "to-zip"}, err
	}
	inspection, err := inspectIPA(*input)
	if err != nil {
		return result{Command: "to-zip"}, err
	}
	destination := *output
	if destination == "" {
		destination = strings.TrimSuffix(inspection.Output, filepath.Ext(inspection.Output)) + ".zip"
	}
	if strings.ToLower(filepath.Ext(destination)) != ".zip" {
		return result{Command: "to-zip"}, errors.New("output must end in .zip")
	}
	absDestination, err := filepath.Abs(destination)
	if err != nil {
		return result{Command: "to-zip"}, err
	}
	if err := copyExclusive(inspection.Output, absDestination); err != nil {
		return result{Command: "to-zip"}, err
	}
	inspection.OK = true
	inspection.Command = "to-zip"
	inspection.ZipOutput = absDestination
	return inspection, nil
}

func copyExclusive(source, destination string) error {
	if _, err := os.Stat(destination); err == nil {
		return errors.New("refusing to overwrite an existing ZIP file")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = out.Close()
		if !complete {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}

func limited(value []byte) string {
	const max = 32 * 1024
	if len(value) > max {
		value = value[len(value)-max:]
	}
	return strings.TrimSpace(string(value))
}
