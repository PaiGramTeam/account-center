package main

import (
	"fmt"
	"log"

	"paigram/initialize/seed"
	"paigram/internal/config"
	"paigram/internal/database"
)

func main() {
	// 加载配置
	cfg := config.MustLoad("config")

	// 连接数据库
	db := database.MustConnect(cfg.Database)

	fmt.Println("=== 测试种子数据初始化 ===")
	fmt.Println()

	// 运行权限和角色种子数据
	fmt.Println("1. 创建权限和角色...")
	if err := seed.Run(db); err != nil {
		log.Fatalf("Failed to run seed: %v", err)
	}
	fmt.Println("✓ 权限和角色创建成功")
	fmt.Println()

	// 创建管理员账号
	fmt.Println("2. 创建管理员账号...")
	if err := seed.CreateDefaultAdmin(db); err != nil {
		log.Fatalf("Failed to create admin: %v", err)
	}
	fmt.Println("✓ 管理员账号创建成功")
	fmt.Println()

	fmt.Println("=== 初始化完成 ===")
	fmt.Println()
	fmt.Println("默认管理员账号信息：")
	fmt.Println("- Email: admin@paigram.local")
	fmt.Println("- Password: admin123456")
	fmt.Println()
	fmt.Println("⚠️  请立即登录并更改默认密码！")
}
