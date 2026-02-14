package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var (
	Mode             = flag.String("mode", "generate", "Mode: generate, fetch, validate")
	OutputFormat     = flag.String("format", "clash", "Output format: clash, singbox, v2ray, raw")
	ConfigSourceFile = flag.String("sources", "config/sources.yaml", "Path to config sources file")
	RulesFile        = flag.String("rules", "config/iran_rules.json", "Path to filtering rules file")
	OutputFile       = flag.String("output", "subscriptions/main.txt", "Output subscription file path")
	MaxConfigs       = flag.Int("max", 5000, "Maximum number of configs to process")
	Verbose          = flag.Bool("v", false, "Verbose output")
)

func main() {
	flag.Parse()

	setupLogging()

	if *Verbose {
		log.Println("Starting Iran-Proxy-Unified aggregator...")
		log.Printf("Mode: %s | Format: %s | Max Configs: %d\n", *Mode, *OutputFormat, *MaxConfigs)
	}

	switch *Mode {
	case "generate":
		if err := handleGenerate(); err != nil {
			log.Fatalf("Error in generate mode: %v", err)
		}
	case "fetch":
		if err := handleFetch(); err != nil {
			log.Fatalf("Error in fetch mode: %v", err)
		}
	case "validate":
		if err := handleValidate(); err != nil {
			log.Fatalf("Error in validate mode: %v", err)
		}
	default:
		log.Fatalf("Unknown mode: %s", *Mode)
	}

	if *Verbose {
		log.Println("Aggregator completed successfully.")
	}
}

func handleGenerate() error {
	if *Verbose {
		log.Println("Loading configurations...")
	}

	// Initialize aggregator
	agg, err := NewAggregator(*ConfigSourceFile, *RulesFile, *MaxConfigs)
	if err != nil {
		return fmt.Errorf("failed to initialize aggregator: %w", err)
	}

	if *Verbose {
		log.Println("Fetching configs from sources...")
	}

	// Fetch and process configurations
	configs, err := agg.FetchAndProcessConfigs()
	if err != nil {
		return fmt.Errorf("failed to fetch configs: %w", err)
	}

	if *Verbose {
		log.Printf("Fetched and processed %d configs\n", len(configs))
	}

	// Generate subscription
	subGen := NewSubscriptionGenerator(*OutputFormat)
	subscription, err := subGen.Generate(configs)
	if err != nil {
		return fmt.Errorf("failed to generate subscription: %w", err)
	}

	if *Verbose {
		log.Printf("Generated subscription (%d bytes)\n", len(subscription))
		log.Printf("Saving to: %s\n", *OutputFile)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(*OutputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save subscription to file
	if err := os.WriteFile(*OutputFile, []byte(subscription), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Subscription generated successfully!\n")
	fmt.Printf("Output: %s\n", *OutputFile)
	fmt.Printf("Configs: %d\n", len(configs))

	return nil
}

func handleFetch() error {
	log.Println("Fetching configs from sources...")
	agg, err := NewAggregator(*ConfigSourceFile, *RulesFile, *MaxConfigs)
	if err != nil {
		return err
	}

	configs, err := agg.FetchAndProcessConfigs()
	if err != nil {
		return err
	}

	fmt.Printf("Successfully fetched %d configs\n", len(configs))
	return nil
}

func handleValidate() error {
	log.Println("Validating configuration files...")

	// Validate sources file
	if _, err := os.Stat(*ConfigSourceFile); err != nil {
		return fmt.Errorf("sources file not found: %w", err)
	}

	// Validate rules file
	if _, err := os.Stat(*RulesFile); err != nil {
		return fmt.Errorf("rules file not found: %w", err)
	}

	fmt.Println("Configuration files validated successfully!")
	return nil
}

func setupLogging() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if !*Verbose {
		log.SetOutput(os.Stderr)
	}
}
