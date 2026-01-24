package main

import (
	"context"
	"fmt"

	"paigram/internal/config"
	"paigram/internal/email"
)

func main() {
	// Test loading templates from files
	cfg := config.EmailConfig{
		Enabled:     false,
		TemplateDir: "./templates/email",
	}

	svc, err := email.NewService(cfg)
	if err != nil {
		panic(err)
	}

	// Test rendering
	err = svc.SendVerificationEmail(
		context.Background(),
		"test@example.com",
		"ABC123",
		"https://example.com",
	)

	if err != nil {
		panic(err)
	}

	fmt.Println("✓ Template loaded and rendered successfully!")
	fmt.Println("\nYou can now:")
	fmt.Println("  1. Edit templates in ./templates/email/")
	fmt.Println("  2. Run: svc.ReloadTemplates() to reload without restart")
	fmt.Println("  3. View changes immediately in development mode")
}
