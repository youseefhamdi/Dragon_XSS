package main

import (
    "fmt"
    "net/http"
    "io/ioutil"
    "strings"
    "time"
)

var payloads = []string{
    "<script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    "';alert(1);//",
}

func RunScan(url string) {
    fmt.Printf("Scanning target: %s\n", url)
    client := &http.Client{Timeout: 10 * time.Second}
    found := false

    for _, payload := range payloads {
        fullURL := url + "?q=" + payload
        resp, err := client.Get(fullURL)
        if err != nil {
            fmt.Printf("Request failed: %v\n", err)
            continue
        }
        body, _ := ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        if strings.Contains(string(body), payload) {
            color.Green("Possible XSS found with payload: %s", payload)
            found = true
        }
    }
    if !found {
        color.Yellow("No XSS found on %s", url)
    }
}
