package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"paigram/initialize/seed"
	"paigram/internal/config"
	"paigram/internal/database"
)

func init() {
	rootCmd.AddCommand(verifyCasbinCmd)
}

var verifyCasbinCmd = &cobra.Command{
	Use:   "verify-casbin",
	Short: "Verify Casbin policies are correctly configured",
	Long:  `Checks seeded system-role Casbin policies against the seed catalog and reports drift.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.MustLoad("config")
		cfg.Database.AutoMigrate = false
		cfg.Database.AutoSeed = false
		db := database.MustConnect(cfg.Database, cfg.Security)

		drift, err := seed.VerifySeedCasbinPolicies(db)
		if err != nil {
			log.Fatalf("Failed to verify Casbin policies: %v", err)
		}

		if len(drift) == 0 {
			log.Println("Casbin verification passed: seeded system-role policies match the catalog")
			return
		}

		log.Println("Casbin verification failed:")
		for _, item := range drift {
			log.Printf("role %s (ID: %s)", item.RoleName, item.RoleID)
			for _, policy := range item.Missing {
				log.Printf("  missing: %s %s", policy[2], policy[1])
			}
			for _, policy := range item.Unexpected {
				log.Printf("  unexpected: %s %s", policy[2], policy[1])
			}
		}
		log.Fatal("Run 'sync-casbin' to reconcile managed Casbin policies")
	},
}
