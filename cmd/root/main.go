package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/client/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	_ "github.com/lib/pq"

	orbitalstore "github.com/openkcm/orbital/store/sql"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/internal/reconciler"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
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

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dsn)
	handleErr(err, "failed to connect to database")
	defer db.Close()

	// run migrations
	err = storesql.Migrate(context.Background(), db)
	handleErr(err, "failed to run migrations")

	// load root configuration
	cfg := loadConfig()

	// store initialization
	tenantStore := storesql.NewTenantStore(db)
	agentStore := storesql.NewAgentStore(db)
	keyStore := storesql.NewKeyStore(db)

	// orbital reconciler setup
	orbitalStore, err := orbitalstore.New(context.Background(), db)
	handleErr(err, "failed to create orbital store")
	repo := orbital.NewRepository(orbitalStore)

	targetProvider := reconciler.TargetProvider(func(_ context.Context, target config.ReconcilerTarget) (orbital.Initiator, error) {
		conn, err := grpc.NewClient(target.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		return rpc.NewClient(conn)
	})

	var reconcilerOpts []reconciler.Option
	if cfg.Reconciler.ExecInterval > 0 {
		reconcilerOpts = append(reconcilerOpts, reconciler.WithExecInterval(cfg.Reconciler.ExecInterval))
	}

	reconcilerMgr, err := reconciler.NewManager(
		context.Background(),
		&cfg.Reconciler,
		repo,
		targetProvider,
		[]reconciler.JobHandler{announcekey.NewJobHandler(keyStore)},
		reconcilerOpts...,
	)
	handleErr(err, "failed to create reconciler manager")

	go func() {
		if err := reconcilerMgr.Start(context.Background()); err != nil {
			log.Printf("reconciler manager stopped: %v", err)
		}
	}()

	// gRPC server setup for admin API
	grpcServer := grpc.NewServer()
	admin.RegisterTenantServiceServer(grpcServer, admin.NewTenantService(tenantStore))

	// gRPC server setup for agent API
	agents.RegisterServiceServer(grpcServer, agents.NewAgentService(agentStore, *cfg))

	// gRPC server setup for keys API
	admin.RegisterKeyServiceServer(grpcServer, admin.NewKeyService(keyStore, reconcilerMgr))

	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ":"+srvPort)
	handleErr(err, "failed to listen on gRPC port")

	go func() {
		log.Printf("gRPC server listening on :%s", srvPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve gRPC: %v", err)
		}
	}()

	// worker initialization
	wrkr := initAgentWorker(agentStore)
	go wrkr.Start(context.Background())

	// graceful shutdown on SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	log.Println("Received shutdown signal, stopping server...")
	grpcServer.GracefulStop()
	wrkr.Stop()
	_ = reconcilerMgr.Stop(context.Background())
	log.Println("Shutdown complete.")
}

func loadConfig() *config.RootConfig {
	path := os.Getenv("ROOT_CONFIG_PATH")
	if path == "" {
		path = "config.yaml"
	}

	rCfg, err := config.LoadRootConfig(path)
	handleErr(err, "failed to load root config from "+path)

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
