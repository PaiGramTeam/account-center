package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"gorm.io/gorm"
	"paigram/internal/casbin"
	"paigram/internal/config"
	"paigram/internal/database"
	"paigram/internal/service"
)

func init() {
	rootCmd.AddCommand(migrateToCasbinCmd)
}

var migrateToCasbinCmd = &cobra.Command{
	Use:   "migrate-to-casbin",
	Short: "将现有权限数据迁移并合并到Casbin",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.MustLoad("config")
		cfg.Database.AutoMigrate = false
		cfg.Database.AutoSeed = false
		db := database.MustConnect(cfg.Database)

		if err := migrateCasbinBootstrap(db); err != nil {
			log.Fatal("Migration failed:", err)
		}

		log.Println("Migration to Casbin completed successfully (existing custom roles preserved)!")
	},
}

func migrateCasbinBootstrap(db *gorm.DB) error {
	if _, err := casbin.InitEnforcer(db); err != nil {
		return err
	}

	serviceGroup := service.NewServiceGroup(db)
	return serviceGroup.CasbinServiceGroup.CasbinService.MigratePermissionsToCasbin()
}
