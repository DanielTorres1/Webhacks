package webhacks

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type WebHacks struct {
	rhost       string
	rport       string
	path        string
	proto       string
	maxRedirect int
	html        string
	finalURL    string
	userAgent   string
	proxyHost   string
	proxyPort   string
	proxyUser   string
	proxyPass   string
	proxyEnv    string
	error404    string
	cookie      string
	ajax        string
	threads     int
	debug       int
	timeout     int
	mostrarTodo int
	headers     http.Header
	browser     *http.Client
}

func NewWebHacks() *WebHacks {
	return &WebHacks{
		rport:       "80",
		path:        "/",
		proto:       "http",
		maxRedirect: 0,
		ajax:        "0",
		threads:     10,
		debug:       0,
		timeout:     15,
		mostrarTodo: 1,
		headers:     make(http.Header),
		browser:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (w *WebHacks) Dirbuster(urlFile string) {
	file, err := os.Open(urlFile)
	if err != nil {
		fmt.Printf("ERROR: Can not open the file %s\n", urlFile)
		return
	}
	defer file.Close()

	var links []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		links = append(links, scanner.Text())
	}

	var wg sync.WaitGroup
	urlsChan := make(chan string, len(links))

	for i := 0; i < w.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlsChan {
				fmt.Println(url) // Replace with actual handling
			}
		}()
	}

	for _, link := range links {
		urlsChan <- link
	}
	close(urlsChan)
	wg.Wait()
}
