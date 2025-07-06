package main

import (
    "fmt"
    "os"
    "github.com/fatih/color"
    "github.com/spf13/cobra"
)

var target string

func displayBanner() {
    banner := `
🐉 DRAGON XSS SCANNER
────────────────────────────────────
🐉 Advanced Web Security Testing Tool

📋 Version: v1.0.0
👨‍💻 Author: Youssef Hamdi

⚠️ For authorized security testing only
────────────────────────────────────────────────────────────────
`
    color.HiRed(banner)
}

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan a target for XSS vulnerabilities",
    Run: func(cmd *cobra.Command, args []string) {
        displayBanner()
        if target == "" {
            fmt.Println("Please provide a target URL with -u or --url")
            return
        }
        RunScan(target)
    },
}

var rootCmd = &cobra.Command{
    Use:   "dragon",
    Short: "Dragon XSS Scanner - Advanced XSS detection tool",
    Run: func(cmd *cobra.Command, args []string) {
        displayBanner()
        cmd.Help()
    },
}

func init() {
    scanCmd.Flags().StringVarP(&target, "url", "u", "", "Target URL to scan")
    rootCmd.AddCommand(scanCmd)
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
