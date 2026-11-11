package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const ruleSGIPv4 = "AWS-SG-INGRESS-IPV4-PUBLIC"

var binary string

func TestMain(m *testing.M) {
	tmp := filepath.Join(os.TempDir(), "iac-policy-gate-test-bin")
	out, err := exec.Command("go", "build", "-o", tmp, ".").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	binary = tmp
	os.Exit(m.Run())
}

func runCLI(args ...string) (int, string, string) {
	cmd := exec.Command(binary, args...)
	cmd.Env = os.Environ()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 99
		}
	}
	return code, stdout.String(), stderr.String()
}

func TestCLI_exitCodes(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "fixtures")
	pass := filepath.Join(root, "pass_clean.synthetic.json")
	fail := filepath.Join(root, "fail_sg_ipv4_public.synthetic.json")
	bad := filepath.Join(root, "fail_format_version.synthetic.json")

	code, _, _ := runCLI("-plan", pass)
	if code != 0 {
		t.Fatalf("pass code %d", code)
	}
	code, _, _ = runCLI("-plan", fail)
	if code != 1 {
		t.Fatalf("policy fail code %d", code)
	}
	code, out, _ := runCLI("-json", "-plan", fail)
	if code != 1 || !strings.Contains(out, ruleSGIPv4) {
		t.Fatalf("json out %s code %d", out, code)
	}
	code, _, _ = runCLI("-plan", bad)
	if code != 3 {
		t.Fatalf("plan error code %d", code)
	}
}
