package main

import (
	"fmt"
	"os"

	"paigram/internal/config"
	"paigram/internal/email"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: export-templates <output-directory>")
		fmt.Println("Example: export-templates ./templates/email")
		os.Exit(1)
	}

	outputDir := os.Args[1]

	// Create email service with disabled config
	svc, err := email.NewService(config.EmailConfig{
		Enabled: false,
	})
	if err != nil {
		fmt.Printf("Error creating email service: %v\n", err)
		os.Exit(1)
	}

	// Export templates
	if err := svc.ExportTemplates(outputDir); err != nil {
		fmt.Printf("Error exporting templates: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Templates exported to: %s\n", outputDir)
	fmt.Println("\nExported files:")
	fmt.Println("  - email_verification.html")
	fmt.Println("  - password_reset.html")
	fmt.Println("  - password_changed.html")
	fmt.Println("  - new_device_login.html")
	fmt.Println("  - 2fa_backup_codes.html")
	fmt.Println("\nNext steps:")
	fmt.Printf("  1. Edit the templates in %s\n", outputDir)
	fmt.Println("  2. Update config.yaml:")
	fmt.Printf("     email:\n       template_dir: %s\n", outputDir)
	fmt.Println("  3. Restart the service")
}
