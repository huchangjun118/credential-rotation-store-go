package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

func main() {
	config := DefaultConfig()
	store, err := NewStore(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create store: %v\n", err)
		os.Exit(1)
	}
	if err := store.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start store: %v\n", err)
		os.Exit(1)
	}
	defer store.Stop()

	ctx := context.Background()
	admin := Actor{ID: "admin-1", Role: RoleAdmin}

	// 签发凭证
	cred, err := store.Issue(ctx, admin, "demo-service", RoleIssuer, time.Hour)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("issued credential: %s\n", cred.ID)

	// 校验凭证
	if err := store.Verify(ctx, cred); err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("credential verified OK")

	// 轮换主密钥
	newGen, err := store.Rotate(ctx, admin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rotate failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("rotated to generation: %d\n", newGen.ID)

	// 旧凭证仍可校验
	if err := store.Verify(ctx, cred); err != nil {
		fmt.Fprintf(os.Stderr, "verify old credential failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("old credential still valid after rotation")

	// 吊销凭证
	if err := store.Revoke(ctx, admin, cred.ID); err != nil {
		fmt.Fprintf(os.Stderr, "revoke failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("credential revoked")

	// 吊销后校验失败
	if err := store.Verify(ctx, cred); err == nil {
		fmt.Fprintln(os.Stderr, "ERROR: revoked credential still valid")
		os.Exit(1)
	} else {
		fmt.Printf("revoked credential rejected: %v\n", err)
	}

	// 查看审计
	records, _ := store.GetAuditLog(ctx)
	fmt.Printf("audit records: %d\n", len(records))
	for _, r := range records {
		fmt.Printf("  [%s] %s actor=%s success=%v detail=%s\n", r.Timestamp.Format(time.RFC3339), r.Action, r.ActorID, r.Success, r.Detail)
	}
}
