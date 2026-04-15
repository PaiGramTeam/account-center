package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"paigram/initialize/seed"
	"paigram/internal/config"
	"paigram/internal/database"
)

func init() {
	rootCmd.AddCommand(syncCasbinCmd)
}

var syncCasbinCmd = &cobra.Command{
	Use:   "sync-casbin",
	Short: "Synchronize permissions into Casbin policies",
	Long: `Reconciles built-in permissions, roles, and managed Casbin policies from the seed catalog.
This is safe to run multiple times and only rewrites managed policies for seeded system roles.`,
	Run: func(cmd *cobra.Command, args []string) {
		runSeedCasbinSync()
	},
}

func runSeedCasbinSync() {
	cfg := config.MustLoad("config")
	cfg.Database.AutoMigrate = false
	cfg.Database.AutoSeed = false
	db := database.MustConnect(cfg.Database)

	log.Println("Synchronizing built-in Casbin state from the seed catalog...")
	if err := seed.SeedPermissions(db); err != nil {
		log.Fatalf("Failed to seed permissions: %v", err)
	}
	if err := seed.SeedRoles(db); err != nil {
		log.Fatalf("Failed to seed roles: %v", err)
	}
	if err := seed.SeedCasbinPolicies(db); err != nil {
		log.Fatalf("Failed to seed Casbin policies: %v", err)
	}

	drift, err := seed.VerifySeedCasbinPolicies(db)
	if err != nil {
		log.Fatalf("Failed to verify Casbin policies after sync: %v", err)
	}
	if len(drift) > 0 {
		log.Fatalf("Sync completed but managed Casbin drift remains for %d role(s)", len(drift))
	}

	log.Println("Managed Casbin policies are now consistent with the seed catalog")
}
