package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/agents"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// Simple krypton server for manual testing and development.
// Not intended for production use (yet).
func main() {
	srvPort := os.Getenv("SERVER_PORT")
	if srvPort == "" {
		srvPort = "8080"
	}
	_, err := strconv.Atoi(srvPort)
	handleErr(err, "invalid SERVER_PORT value")

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "9090"
	}
	_, err = strconv.Atoi(grpcPort)
	handleErr(err, "invalid GRPC_PORT value")

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dsn)
	handleErr(err, "failed to connect to database")
	defer db.Close()

	// load root configuration
	cfg := loadConfig()

	// tenant store initialization
	tenantStore, err := storesql.NewTenantStore(context.Background(), db)
	handleErr(err, "failed to initialize store")

	// agent store initialization
	agentStore, err := storesql.NewAgentStore(context.Background(), db)
	handleErr(err, "failed to initialize store")

	// gRPC server setup for admin API
	grpcServer := grpc.NewServer()
	admin.RegisterServiceServer(grpcServer, admin.NewService(tenantStore))

	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ":"+grpcPort)
	handleErr(err, "failed to listen on gRPC port")

	go func() {
		log.Printf("gRPC server listening on :%s", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve gRPC: %v", err)
		}
	}()
	defer grpcServer.GracefulStop()

	// HTTP API server setup (for agents API where http client is still used in tests)
	mux := agents.NewServerMux(nil, agentStore, *cfg)

	// worker initialization
	wrkr := initAgentWorker(agentStore)
	go wrkr.Start(context.Background())
	defer wrkr.Stop()

	log.Printf("HTTP server listening on :%s", srvPort)
	err = http.ListenAndServe(":"+srvPort, mux)
	handleErr(err, "failed to start server")
}

// For simplicity, we hardcode a sample root configuration here.
func loadConfig() *config.RootConfig {
	rCfg, err := config.LoadRootConfig(os.Getenv("ROOT_CONFIG_PATH"))
	if err != nil {
		rCfg = &config.RootConfig{
			Name: "root",
			Role: spec.RootRole,
			Segment: spec.HierarchySegment{
				StartKind: "K0",
				EndKind:   "K1",
			},
			Labels: spec.Labels{
				"environment": "production",
			},
			KeyBindings: map[string]spec.KeyBinding{
				"K0": {
					Vault: spec.VaultSpec{
						Name: "root-hsm-vault",
						Type: "aws-kms",
					},
				},
				"K1": {
					Vault: spec.VaultSpec{
						Name: "root-vault",
						Type: "open-bao",
					},
					ParentKeyProvider: &spec.ParentKeyProviderRef{
						AgentName: "root",
					},
				},
			},
			Hierarchy: spec.KeyHierarchy{
				Name: "production-hierarchy",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: "root", Algorithm: "AES256"},
					{Kind: "K1", Role: "kek", Algorithm: "AES256"},
					{Kind: "K2", Role: "tek", Algorithm: "AES256"},
					{Kind: "K3", Role: "dek", Algorithm: "AES256"},
				},
			},
			Topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "agent-k1",
						Segment: spec.HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {
								Vault: spec.VaultSpec{
									Name: "aws-vault",
									Type: "aws-kms",
								},
								ParentKeyProvider: &spec.ParentKeyProviderRef{
									AgentName: "root",
								},
							},
							"K3": {
								Vault: spec.VaultSpec{
									Name: "aws-dek-vault",
									Type: "aws-kms",
								},
							},
						},
						Labels: spec.Labels{
							"cloud": "aws",
						},
					},
				},
			},
		}
	}
	return rCfg
}

// Worker to periodically check agent heartbeats and update their registration status accordingly.
func initAgentWorker(agentStore *storesql.AgentStore) *worker.Scheduler {
	agentRegWorker, err := worker.New(10*time.Second, func(ctx context.Context) error {
		// Mark agents as Unhealthy if they haven't sent a heartbeat within the last 30 seconds.
		err1 := agentStore.UpdateStatus(ctx, store.UpdateAgentStatusQuery{
			FromStatus:         []core.AgentRegistrationStatus{core.AgentRegistrationStatusRegistered, core.AgentRegistrationStatusHealthy},
			ToStatus:           core.AgentRegistrationStatusUnhealthy,
			HeartbeatThreshold: time.Second * 30,
		})

		// Deregister agents that have been Unhealthy for more than 90 seconds.
		err2 := agentStore.UpdateStatus(ctx, store.UpdateAgentStatusQuery{
			FromStatus:         []core.AgentRegistrationStatus{core.AgentRegistrationStatusUnhealthy},
			ToStatus:           core.AgentRegistrationStatusDeregistered,
			HeartbeatThreshold: time.Second * 90,
		})

		// Optionally, we can also delete deregistered agents after some time to keep the database clean.
		err3 := agentStore.Delete(ctx, store.DeleteAgentQuery{
			Status:             core.AgentRegistrationStatusDeregistered,
			HeartbeatThreshold: time.Second * 91,
		})

		return errors.Join(err1, err2, err3)
	})

	handleErr(err, "failed to create agent registration worker")

	return agentRegWorker
}

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
