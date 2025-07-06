package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Banner الخاص بالأداة
func displayBanner() {
	banner := `
🐉 DRAGON XSS SCANNER
────────────────────────────────────────────────────────────────
🐉 Advanced Web Security Testing Tool - Professional Edition

📋 Version: v2.1.0 Professional
👨‍💻 Author: Youssef Hamdi
🌐 GitHub: github.com/youssefhamdi/Dragon_XSS
🔥 Features: WAF Bypass | DOM XSS | AI-Powered | Multi-Threading

⚠️  FOR AUTHORIZED SECURITY TESTING ONLY
────────────────────────────────────────────────────────────────
`
	color.HiRed(banner)
}

// متغيرات للأوامر
var (
	targetURL      string
	subdomainFile  string
	outputFile     string
	threads        int
	rateLimit      int
	timeout        int
	enableEncoding bool
	enableWAF      bool
	enableDOM      bool
	enableAI       bool
	verboseMode    bool
	payloadFile    string
	userAgent      string
	proxy          string
)

// أمر الفحص الرئيسي
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan target(s) for XSS vulnerabilities",
	Long: `Scan single target or multiple subdomains for XSS vulnerabilities.
Supports all XSS types: Reflected, Stored, DOM-based, and Blind XSS.
Includes advanced WAF bypass and encoding techniques.`,
	Run: func(cmd *cobra.Command, args []string) {
		displayBanner()
		
		// التحقق من المدخلات
		if targetURL == "" && subdomainFile == "" {
			color.Red("❌ Error: Please provide either -u (target URL) or -l (subdomain list)")
			fmt.Println("\nExamples:")
			fmt.Println("  ./dragon scan -u https://target.com")
			fmt.Println("  ./dragon scan -l subdomains.txt")
			return
		}

		// إعداد الماسح
		scanner := NewDragonScanner(&ScanConfig{
			Threads:        threads,
			RateLimit:      rateLimit,
			Timeout:        timeout,
			EnableEncoding: enableEncoding,
			EnableWAF:      enableWAF,
			EnableDOM:      enableDOM,
			EnableAI:       enableAI,
			VerboseMode:    verboseMode,
			UserAgent:      userAgent,
			Proxy:          proxy,
			PayloadFile:    payloadFile,
		})

		var results []ScanResult

		// بدء الفحص
		if targetURL != "" {
			// فحص هدف واحد
			color.Cyan("🎯 Starting single target scan...")
			color.Yellow("Target: %s", targetURL)
			
			result := scanner.ScanSingleTarget(targetURL)
			results = append(results, result)
		} else {
			// فحص قائمة subdomains
			color.Cyan("🎯 Starting subdomain list scan...")
			color.Yellow("File: %s", subdomainFile)
			
			targets, err := readSubdomainFile(subdomainFile)
			if err != nil {
				color.Red("❌ Error reading subdomain file: %v", err)
				return
			}
			
			color.Green("📝 Loaded %d targets from file", len(targets))
			results = scanner.ScanMultipleTargets(targets)
		}

		// عرض النتائج
		displayResults(results)

		// حفظ النتائج إذا تم تحديد ملف الإخراج
		if outputFile != "" {
			saveResults(results, outputFile)
		}
	},
}

// أمر عرض معلومات الإصدار
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		displayBanner()
		fmt.Println()
		color.HiGreen("🐉 Dragon XSS Scanner Professional Edition")
		color.White("Version: v2.1.0")
		color.White("Author: Youssef Hamdi")
		color.White("Release Date: July 2025")
		color.White("License: MIT")
		fmt.Println()
		color.HiYellow("Features:")
		fmt.Println("  ✅ Advanced XSS Detection (Reflected, Stored, DOM, Blind)")
		fmt.Println("  ✅ WAF Bypass (Cloudflare, ModSecurity, AWS, Azure)")
		fmt.Println("  ✅ 10+ Encoding Techniques")
		fmt.Println("  ✅ AI-Powered Classification")
		fmt.Println("  ✅ Multi-threaded Scanning")
		fmt.Println("  ✅ Professional Reporting")
	},
}

// أمر عرض معلومات المطور
var creditsCmd = &cobra.Command{
	Use:   "credits",
	Short: "Show credits and author information",
	Run: func(cmd *cobra.Command, args []string) {
		displayBanner()
		fmt.Println()
		color.HiCyan("👨‍💻 DEVELOPER INFORMATION")
		color.White("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		color.HiGreen("Name: Youssef Hamdi")
		color.White("Role: Security Researcher & Developer")
		color.White("Specialization: Web Application Security")
		color.White("GitHub: @youssefhamdi")
		fmt.Println()
		color.HiYellow("🎯 MISSION")
		color.White("Creating advanced security tools to help")
		color.White("security professionals identify and fix")
		color.White("web application vulnerabilities.")
		fmt.Println()
		color.HiMagenta("⚖️  ETHICS")
		color.White("This tool is designed for:")
		fmt.Println("  • Authorized penetration testing")
		fmt.Println("  • Security research")
		fmt.Println("  • Bug bounty hunting")
		fmt.Println("  • Educational purposes")
		fmt.Println()
		color.Red("⚠️  Always obtain proper authorization before testing!")
	},
}

// أمر إنشاء ملف payloads مخصص
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate custom payload files",
	Run: func(cmd *cobra.Command, args []string) {
		displayBanner()
		color.Cyan("🔧 Generating custom payload files...")
		
		// إنشاء ملف payloads أساسي
		basicPayloads := GetBasicXSSPayloads()
		
		filename := "custom_payloads.txt"
		file, err := os.Create(filename)
		if err != nil {
			color.Red("❌ Error creating file: %v", err)
			return
		}
		defer file.Close()

		for _, payload := range basicPayloads {
			file.WriteString(payload + "\n")
		}

		color.Green("✅ Generated %d payloads in %s", len(basicPayloads), filename)
		
		// إنشاء ملف subdomains مثال
		subfilename := "example_subdomains.txt"
		subfile, err := os.Create(subfilename)
		if err != nil {
			color.Red("❌ Error creating subdomain file: %v", err)
			return
		}
		defer subfile.Close()

		exampleSubs := []string{
			"admin.example.com",
			"api.example.com",
			"test.example.com",
			"dev.example.com",
			"staging.example.com",
		}

		for _, sub := range exampleSubs {
			subfile.WriteString(sub + "\n")
		}

		color.Green("✅ Generated example subdomain list in %s", subfilename)
	},
}

// الأمر الجذر
var rootCmd = &cobra.Command{
	Use:   "dragon",
	Short: "Dragon XSS Scanner - Professional XSS Detection Tool",
	Long: `Dragon XSS Scanner is an advanced, professional-grade tool for detecting
Cross-Site Scripting (XSS) vulnerabilities in web applications.

Features:
• All XSS types: Reflected, Stored, DOM-based, Blind
• Advanced WAF bypass techniques
• 10+ encoding methods
• AI-powered classification
• Multi-threaded scanning
• Professional reporting`,
	Run: func(cmd *cobra.Command, args []string) {
		displayBanner()
		fmt.Println()
		color.HiCyan("🚀 Welcome to Dragon XSS Scanner Professional!")
		fmt.Println()
		color.White("Use 'dragon --help' to see all available commands.")
		color.White("Use 'dragon scan --help' for scanning options.")
		fmt.Println()
		color.HiYellow("Quick Examples:")
		fmt.Println("  dragon scan -u https://target.com")
		fmt.Println("  dragon scan -l subdomains.txt --waf-bypass")
		fmt.Println("  dragon generate  # Create sample files")
		fmt.Println()
	},
}

// إعداد الأوامر والخيارات
func init() {
	// إضافة الأوامر الفرعية
	rootCmd.AddCommand(scanCmd, versionCmd, creditsCmd, generateCmd)

	// خيارات أمر الفحص
	scanCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target URL to scan")
	scanCmd.Flags().StringVarP(&subdomainFile, "list", "l", "", "File containing list of subdomains/URLs")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results (JSON format)")
	scanCmd.Flags().IntVarP(&threads, "threads", "t", 50, "Number of concurrent threads")
	scanCmd.Flags().IntVarP(&rateLimit, "rate", "r", 100, "Requests per second limit")
	scanCmd.Flags().IntVar(&timeout, "timeout", 10, "HTTP timeout in seconds")
	scanCmd.Flags().BoolVar(&enableEncoding, "encoding", false, "Enable advanced encoding bypass")
	scanCmd.Flags().BoolVar(&enableWAF, "waf-bypass", false, "Enable WAF bypass techniques")
	scanCmd.Flags().BoolVar(&enableDOM, "dom-analysis", false, "Enable DOM XSS analysis")
	scanCmd.Flags().BoolVar(&enableAI, "ai-classification", false, "Enable AI-powered classification")
	scanCmd.Flags().BoolVarP(&verboseMode, "verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().StringVar(&payloadFile, "payloads", "", "Custom payload file")
	scanCmd.Flags().StringVar(&userAgent, "user-agent", "Dragon XSS Scanner v2.1.0", "Custom User-Agent")
	scanCmd.Flags().StringVar(&proxy, "proxy", "", "HTTP proxy (http://proxy:port)")
}

// قراءة ملف subdomains
func readSubdomainFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// إضافة https:// إذا لم يكن موجوداً
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				line = "https://" + line
			}
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

// عرض النتائج
func displayResults(results []ScanResult) {
	fmt.Println()
	color.HiCyan("🔍 SCAN RESULTS")
	color.White("═══════════════════════════════════════════════════")
	
	totalScanned := len(results)
	vulnerableCount := 0
	totalVulns := 0

	for _, result := range results {
		if len(result.Vulnerabilities) > 0 {
			vulnerableCount++
			totalVulns += len(result.Vulnerabilities)
		}
	}

	// إحصائيات سريعة
	color.HiGreen("📊 SUMMARY:")
	fmt.Printf("  Total Scanned: %d\n", totalScanned)
	fmt.Printf("  Vulnerable Sites: %d\n", vulnerableCount)
	fmt.Printf("  Total Vulnerabilities: %d\n", totalVulns)
	fmt.Println()

	// تفاصيل النتائج
	for _, result := range results {
		if len(result.Vulnerabilities) > 0 {
			color.HiRed("🚨 VULNERABLE: %s", result.URL)
			color.Yellow("   Status: %d | Server: %s", result.StatusCode, result.Server)
			
			for _, vuln := range result.Vulnerabilities {
				color.Red("   ├─ Type: %s", vuln.Type)
				color.Red("   ├─ Parameter: %s", vuln.Parameter)
				color.Red("   ├─ Payload: %s", vuln.Payload)
				color.Red("   ├─ Context: %s", vuln.Context)
				color.Red("   ├─ Severity: %s", vuln.Severity)
				color.Red("   └─ PoC: %s", vuln.PoC)
				fmt.Println()
			}
		} else if verboseMode {
			color.Green("✅ SAFE: %s (Status: %d)", result.URL, result.StatusCode)
		}
	}
}

// حفظ النتائج
func saveResults(results []ScanResult, filename string) {
	data, err := json.MarshalIndent(results, "", "    ")
	if err != nil {
		color.Red("❌ Error marshaling results: %v", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		color.Red("❌ Error writing to file: %v", err)
		return
	}

	color.Green("✅ Results saved to %s", filename)
}

// النقطة الرئيسية للتطبيق
func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("❌ Error: %v", err)
		os.Exit(1)
	}
}