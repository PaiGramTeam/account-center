package email

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"

	"paigram/internal/logging"
)

// TemplateManager manages email templates
type TemplateManager struct {
	templates   map[string]*template.Template
	templateDir string
	mu          sync.RWMutex
	useFiles    bool
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(templateDir string) (*TemplateManager, error) {
	tm := &TemplateManager{
		templates:   make(map[string]*template.Template),
		templateDir: templateDir,
		useFiles:    templateDir != "",
	}

	if tm.useFiles {
		// Load templates from files
		if err := tm.loadTemplatesFromFiles(); err != nil {
			logging.Warn("failed to load templates from files, using embedded templates",
				zap.Error(err),
				zap.String("template_dir", templateDir),
			)
			tm.useFiles = false
			tm.loadEmbeddedTemplates()
		}
	} else {
		// Use embedded templates
		tm.loadEmbeddedTemplates()
	}

	return tm, nil
}

// loadTemplatesFromFiles loads templates from external files
func (tm *TemplateManager) loadTemplatesFromFiles() error {
	if tm.templateDir == "" {
		return fmt.Errorf("template directory not configured")
	}

	// Check if directory exists
	if _, err := os.Stat(tm.templateDir); os.IsNotExist(err) {
		return fmt.Errorf("template directory does not exist: %s", tm.templateDir)
	}

	templateFiles := map[string]string{
		"email_verification": "email_verification.html",
		"password_reset":     "password_reset.html",
		"password_changed":   "password_changed.html",
		"new_device_login":   "new_device_login.html",
		"2fa_backup_codes":   "2fa_backup_codes.html",
		"suspicious_login":   "suspicious_login.html",
	}

	for name, filename := range templateFiles {
		filePath := filepath.Join(tm.templateDir, filename)

		// Read template file
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read template %s: %w", name, err)
		}

		// Parse template
		tmpl, err := template.New(name).Funcs(templateFuncs).Parse(string(content))
		if err != nil {
			return fmt.Errorf("parse template %s: %w", name, err)
		}

		tm.templates[name] = tmpl
		logging.Info("loaded template from file",
			zap.String("name", name),
			zap.String("file", filePath),
		)
	}

	return nil
}

// loadEmbeddedTemplates loads embedded templates
func (tm *TemplateManager) loadEmbeddedTemplates() {
	tm.templates["email_verification"] = template.Must(template.New("email_verification").Funcs(templateFuncs).Parse(emailVerificationTemplate))
	tm.templates["password_reset"] = template.Must(template.New("password_reset").Funcs(templateFuncs).Parse(passwordResetTemplate))
	tm.templates["password_changed"] = template.Must(template.New("password_changed").Funcs(templateFuncs).Parse(passwordChangedTemplate))
	tm.templates["new_device_login"] = template.Must(template.New("new_device_login").Funcs(templateFuncs).Parse(newDeviceLoginTemplate))
	tm.templates["2fa_backup_codes"] = template.Must(template.New("2fa_backup_codes").Funcs(templateFuncs).Parse(twoFactorBackupCodesTemplate))
	tm.templates["suspicious_login"] = template.Must(template.New("suspicious_login").Funcs(templateFuncs).Parse(suspiciousLoginTemplate))

	logging.Info("loaded embedded email templates", zap.Int("count", len(tm.templates)))
}

// GetTemplate returns a template by name
func (tm *TemplateManager) GetTemplate(name string) (*template.Template, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tmpl, ok := tm.templates[name]
	if !ok {
		return nil, fmt.Errorf("template not found: %s", name)
	}

	return tmpl, nil
}

// Reload reloads templates from files (useful for development)
func (tm *TemplateManager) Reload() error {
	if !tm.useFiles {
		return fmt.Errorf("cannot reload: using embedded templates")
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Clear existing templates
	tm.templates = make(map[string]*template.Template)

	// Reload from files
	return tm.loadTemplatesFromFiles()
}

// ExportTemplates exports embedded templates to files
func (tm *TemplateManager) ExportTemplates(outputDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	templates := map[string]string{
		"email_verification.html": emailVerificationTemplate,
		"password_reset.html":     passwordResetTemplate,
		"password_changed.html":   passwordChangedTemplate,
		"new_device_login.html":   newDeviceLoginTemplate,
		"2fa_backup_codes.html":   twoFactorBackupCodesTemplate,
	}

	for filename, content := range templates {
		filePath := filepath.Join(outputDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("write template %s: %w", filename, err)
		}
		logging.Info("exported template",
			zap.String("file", filePath),
		)
	}

	return nil
}

// ListTemplates returns all available template names
func (tm *TemplateManager) ListTemplates() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	names := make([]string, 0, len(tm.templates))
	for name := range tm.templates {
		names = append(names, name)
	}
	return names
}
