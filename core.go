package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// تكوين الفحص
type ScanConfig struct {
	Threads        int
	RateLimit      int
	Timeout        int
	EnableEncoding bool
	EnableWAF      bool
	EnableDOM      bool
	EnableAI       bool
	VerboseMode    bool
	UserAgent      string
	Proxy          string
	PayloadFile    string
}

// نتيجة الفحص
type ScanResult struct {
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	Title           string            `json:"title"`
	Server          string            `json:"server"`
	ContentType     string            `json:"content_type"`
	ResponseTime    time.Duration     `json:"response_time"`
	IsAlive         bool              `json:"is_alive"`
	Vulnerabilities []XSSVulnerability `json:"vulnerabilities"`
	WAFDetected     string            `json:"waf_detected,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
}

// ثغرة XSS
type XSSVulnerability struct {
	Type      string `json:"type"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Context   string `json:"context"`
	Severity  string `json:"severity"`
	PoC       string `json:"poc"`
	Encoding  string `json:"encoding,omitempty"`
}

// ماسح Dragon
type DragonScanner struct {
	config     *ScanConfig
	client     *http.Client
	payloads   []string
	wafDetector *WAFDetector
	encoder    *EncodingEngine
	results    []ScanResult
	mu         sync.Mutex
}

// إنشاء ماسح جديد
func NewDragonScanner(config *ScanConfig) *DragonScanner {
	// إعداد HTTP Client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	// إعداد البروكسي إذا تم تحديده
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // عدم متابعة إعادة التوجيه
		},
	}

	// تحميل الـ payloads
	var payloads []string
	if config.PayloadFile != "" {
		payloads = loadCustomPayloads(config.PayloadFile)
	} else {
		payloads = GetBasicXSSPayloads()
		if config.EnableEncoding {
			payloads = append(payloads, GetAdvancedXSSPayloads()...)
		}
		if config.EnableWAF {
			payloads = append(payloads, GetWAFBypassPayloads()...)
		}
	}

	return &DragonScanner{
		config:      config,
		client:      client,
		payloads:    payloads,
		wafDetector: NewWAFDetector(),
		encoder:     NewEncodingEngine(),
		results:     make([]ScanResult, 0),
	}
}

// فحص هدف واحد
func (d *DragonScanner) ScanSingleTarget(target string) ScanResult {
	if d.config.VerboseMode {
		color.Yellow("🔍 Scanning: %s", target)
	}

	result := ScanResult{
		URL:             target,
		Vulnerabilities: make([]XSSVulnerability, 0),
		Timestamp:       time.Now(),
	}

	// فحص أولي للهدف
	d.performInitialCheck(&result)

	// فحص ثغرات XSS إذا كان الموقع متاحاً
	if result.IsAlive {
		d.performXSSCheck(&result)
	}

	return result
}

// فحص أهداف متعددة
func (d *DragonScanner) ScanMultipleTargets(targets []string) []ScanResult {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.config.Threads)
	results := make([]ScanResult, len(targets))

	startTime := time.Now()
	color.Cyan("🚀 Starting scan of %d targets with %d threads...", len(targets), d.config.Threads)

	for i, target := range targets {
		wg.Add(1)
		go func(index int, url string) {
			defer wg.Done()
			semaphore <- struct{}{} // الحصول على semaphore
			defer func() { <-semaphore }() // تحرير semaphore

			// Rate limiting
			time.Sleep(time.Second / time.Duration(d.config.RateLimit))

			result := d.ScanSingleTarget(url)
			results[index] = result

			// عرض التقدم
			if d.config.VerboseMode {
				if len(result.Vulnerabilities) > 0 {
					color.Red("🚨 [%d/%d] VULNERABLE: %s (%d vulns)", 
						index+1, len(targets), url, len(result.Vulnerabilities))
				} else {
					color.Green("✅ [%d/%d] SAFE: %s", index+1, len(targets), url)
				}
			}
		}(i, target)
	}

	wg.Wait()
	duration := time.Since(startTime)
	
	color.HiGreen("🎉 Scan completed in %v", duration)
	return results
}

// فحص أولي للهدف
func (d *DragonScanner) performInitialCheck(result *ScanResult) {
	start := time.Now()
	
	req, err := http.NewRequest("GET", result.URL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	resp, err := d.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ResponseTime = time.Since(start)
	result.IsAlive = (resp.StatusCode >= 200 && resp.StatusCode < 400)
	
	// استخراج معلومات إضافية
	if server := resp.Header.Get("Server"); server != "" {
		result.Server = server
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		result.ContentType = contentType
	}

	// كشف WAF إذا تم تفعيله
	if d.config.EnableWAF {
		result.WAFDetected = d.wafDetector.DetectWAF(resp)
	}
}

// فحص ثغرات XSS
func (d *DragonScanner) performXSSCheck(result *ScanResult) {
	// البحث عن معاملات في URL
	parameters := d.extractParameters(result.URL)
	
	// إذا لم توجد معاملات، جرب معاملات افتراضية
	if len(parameters) == 0 {
		parameters = []string{"q", "search", "query", "s", "keyword", "id", "page", "name"}
	}

	// فحص كل معامل مع كل payload
	for _, param := range parameters {
		for _, payload := range d.payloads {
			vuln := d.testXSSPayload(result.URL, param, payload)
			if vuln != nil {
				result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
				
				// إذا تم العثور على ثغرة، جرب تقنيات encoding
				if d.config.EnableEncoding {
					encodedVulns := d.testEncodedPayloads(result.URL, param, payload)
					result.Vulnerabilities = append(result.Vulnerabilities, encodedVulns...)
				}
			}
		}
	}

	// فحص DOM XSS إذا تم تفعيله
	if d.config.EnableDOM {
		domVulns := d.testDOMXSS(result.URL)
		result.Vulnerabilities = append(result.Vulnerabilities, domVulns...)
	}
}

// اختبار payload واحد
func (d *DragonScanner) testXSSPayload(baseURL, parameter, payload string) *XSSVulnerability {
	// بناء URL مع payload
	testURL := d.buildTestURL(baseURL, parameter, payload)
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	
	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// قراءة محتوى الاستجابة
	body := make([]byte, 10240) // قراءة أول 10KB فقط
	n, _ := resp.Body.Read(body)
	responseBody := string(body[:n])

	// فحص انعكاس payload
	if d.isPayloadReflected(responseBody, payload) {
		return &XSSVulnerability{
			Type:      "Reflected XSS",
			Parameter: parameter,
			Payload:   payload,
			Context:   d.detectContext(responseBody, payload),
			Severity:  d.assessSeverity(payload),
			PoC:       testURL,
		}
	}

	return nil
}

// اختبار payloads مشفرة
func (d *DragonScanner) testEncodedPayloads(baseURL, parameter, payload string) []XSSVulnerability {
	var vulns []XSSVulnerability
	
	// جرب تقنيات encoding مختلفة
	encodings := []struct {
		name string
		func func(string) string
	}{
		{"URL Encoding", URLEncode},
		{"HTML Entity", HTMLEntityEncode},
		{"Unicode", UnicodeEncode},
		{"Base64", Base64Encode},
		{"Double URL", DoubleURLEncode},
		{"Mixed Case", MixedCaseEncode},
	}

	for _, enc := range encodings {
		encodedPayload := enc.func(payload)
		vuln := d.testXSSPayload(baseURL, parameter, encodedPayload)
		if vuln != nil {
			vuln.Encoding = enc.name
			vuln.Payload = encodedPayload
			vulns = append(vulns, *vuln)
		}
	}

	return vulns
}

// اختبار DOM XSS
func (d *DragonScanner) testDOMXSS(baseURL string) []XSSVulnerability {
	var vulns []XSSVulnerability
	
	// DOM XSS payloads خاصة
	domPayloads := []string{
		"javascript:alert('DOM-XSS')",
		"#<img src=x onerror=alert('DOM-XSS')>",
		"#<script>alert('DOM-XSS')</script>",
		"data:text/html,<script>alert('DOM-XSS')</script>",
	}

	for _, payload := range domPayloads {
		testURL := baseURL + payload
		
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)
		
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// فحص بسيط للـ DOM XSS (يحتاج تطوير أكثر مع headless browser)
		if resp.StatusCode == 200 {
			vuln := &XSSVulnerability{
				Type:      "DOM-based XSS",
				Parameter: "URL Fragment",
				Payload:   payload,
				Context:   "URL",
				Severity:  "Medium",
				PoC:       testURL,
			}
			vulns = append(vulns, *vuln)
		}
	}

	return vulns
}

// استخراج معاملات من URL
func (d *DragonScanner) extractParameters(targetURL string) []string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return []string{}
	}

	var params []string
	for param := range u.Query() {
		params = append(params, param)
	}

	return params
}

// بناء URL للاختبار
func (d *DragonScanner) buildTestURL(baseURL, parameter, payload string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	query := u.Query()
	query.Set(parameter, payload)
	u.RawQuery = query.Encode()

	return u.String()
}

// فحص انعكاس payload
func (d *DragonScanner) isPayloadReflected(responseBody, payload string) bool {
	// فحص مباشر
	if strings.Contains(responseBody, payload) {
		return true
	}

	// فحص encoded versions
	encodedVersions := []string{
		strings.ToLower(payload),
		strings.ToUpper(payload),
		url.QueryEscape(payload),
		HTMLEntityEncode(payload),
	}

	for _, encoded := range encodedVersions {
		if strings.Contains(responseBody, encoded) {
			return true
		}
	}

	return false
}

// كشف سياق الثغرة
func (d *DragonScanner) detectContext(responseBody, payload string) string {
	lowerResponse := strings.ToLower(responseBody)
	lowerPayload := strings.ToLower(payload)

	patterns := []struct {
		pattern string
		context string
	}{
		{fmt.Sprintf("<script[^>]*>.*%s.*</script>", regexp.QuoteMeta(lowerPayload)), "Script Tag"},
		{fmt.Sprintf("=\"[^\"]*%s[^\"]*\"", regexp.QuoteMeta(lowerPayload)), "Attribute Value"},
		{fmt.Sprintf("on\\w+\\s*=\\s*['\"][^'\"]*%s", regexp.QuoteMeta(lowerPayload)), "Event Handler"},
		{fmt.Sprintf("<[^>]*%s[^>]*>", regexp.QuoteMeta(lowerPayload)), "HTML Tag"},
		{fmt.Sprintf("<!--.*%s.*-->", regexp.QuoteMeta(lowerPayload)), "HTML Comment"},
	}

	for _, p := range patterns {
		matched, _ := regexp.MatchString(p.pattern, lowerResponse)
		if matched {
			return p.context
		}
	}

	return "HTML Body"
}

// تقييم خطورة الثغرة
func (d *DragonScanner) assessSeverity(payload string) string {
	payload = strings.ToLower(payload)

	// High severity indicators
	highRisk := []string{"script", "onerror", "onload", "eval", "alert", "confirm", "prompt"}
	for _, risk := range highRisk {
		if strings.Contains(payload, risk) {
			return "High"
		}
	}

	// Medium severity indicators
	mediumRisk := []string{"img", "svg", "iframe", "object", "embed"}
	for _, risk := range mediumRisk {
		if strings.Contains(payload, risk) {
			return "Medium"
		}
	}

	return "Low"
}

// تحميل payloads مخصصة
func loadCustomPayloads(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		color.Red("❌ Error loading custom payloads: %v", err)
		return GetBasicXSSPayloads()
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}

	if len(payloads) == 0 {
		color.Yellow("⚠️  Custom payload file is empty, using default payloads")
		return GetBasicXSSPayloads()
	}

	color.Green("✅ Loaded %d custom payloads", len(payloads))
	return payloads
}