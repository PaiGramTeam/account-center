package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"paigram/internal/testutil/integrationenv"
)

func main() {
	env, err := integrationenv.Load(integrationenv.LoadOptions{})
	if err != nil {
		fail("load integration env", err)
	}

	missing := env.MissingRequired()
	if len(missing) > 0 {
		fmt.Println("Integration environment is incomplete.")
		fmt.Printf("Missing required variables: %s\n", strings.Join(missing, ", "))
		printSummary(env)
		os.Exit(1)
	}

	printSummary(env)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := env.CheckMySQL(ctx); err != nil {
		fail("mysql connectivity", err)
	}
	fmt.Println("mysql.check=ok")

	if err := env.CheckRedis(ctx); err != nil {
		fail("redis connectivity", err)
	}
	fmt.Println("redis.check=ok")
}

func printSummary(env integrationenv.Env) {
	for _, line := range env.SummaryLines("doctor", true) {
		fmt.Println(line)
	}
}

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", step, err)
	os.Exit(1)
}
