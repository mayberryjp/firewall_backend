package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemonProcess(t *testing.T) {
	if os.Getenv("NETCONTROL_TEST_DAEMON") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"netcontrold"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("netcontrold", flag.ExitOnError)
	main()
	os.Exit(0)
}

func daemonCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestDaemonProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "NETCONTROL_TEST_DAEMON=1")
	cmd.Dir = t.TempDir()
	return cmd
}

func TestHTTPWildcardListener(t *testing.T) {
	cmd := daemonCommand(t, "-listen", "0.0.0.0:0")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Errorf("stop daemon: %v", err)
		}
		_ = cmd.Wait()
	})
	address := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			var entry struct {
				Message string `json:"msg"`
				Address string `json:"address"`
			}
			if json.Unmarshal(scanner.Bytes(), &entry) == nil && entry.Message == "management API listening" {
				address <- entry.Address
			}
		}
		close(address)
	}()
	var listener string
	select {
	case listener = <-address:
		if listener == "" {
			t.Fatal("daemon exited without starting the HTTP listener")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for HTTP listener")
	}
	_, port, err := net.SplitHostPort(listener)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for _, host := range []string{"127.0.0.1", "127.0.0.2"} {
		for _, check := range []struct {
			path string
			code int
		}{{"/", 200}, {"/auth/status", 200}, {"/api/v1/state", 401}} {
			resp, err := client.Get("http://" + net.JoinHostPort(host, port) + check.path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != check.code {
				t.Fatalf("%s %s: got %d, want %d", host, check.path, resp.StatusCode, check.code)
			}
		}
	}
}

func TestTLSRequiresCertificateAndKey(t *testing.T) {
	for _, arg := range []string{"-tls-cert", "-tls-key"} {
		cmd := daemonCommand(t, arg, filepath.Join(t.TempDir(), "missing.pem"))
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "both -tls-cert and -tls-key are required together") {
			t.Fatalf("%s: %v: %s", arg, err, output)
		}
	}
}

func TestInvalidListener(t *testing.T) {
	cmd := daemonCommand(t, "-listen", "invalid-address")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "missing port in address") {
		t.Fatalf("invalid listener: %v: %s", err, output)
	}
}

func TestPackagedListener(t *testing.T) {
	config, err := os.ReadFile(filepath.Join("..", "..", "packaging", "alpine", "netcontrold.confd"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "-listen 0.0.0.0:8080") {
		t.Fatal("Alpine package must bind the HTTP listener to all IPv4 interfaces")
	}
	cmd := daemonCommand(t, "-h")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), `(default "0.0.0.0:8080")`) {
		t.Fatalf("daemon listener default: %v: %s", err, output)
	}
}
