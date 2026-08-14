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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	_ "github.com/lib/pq"

	orbitalstore "github.com/openkcm/orbital/store/sql"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/internal/interceptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/reconciler"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
	"github.com/openkcm/krypton/pkg/validator"
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
	keyVersionStore := storesql.NewKeyVersionStore(db)
	transactor := storesql.NewTransactor(db)

	keyValidator := validator.NewValidator(cfg.Segment, cfg.Topology, cfg.Hierarchy, tenantStore, keyStore)

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
		[]reconciler.JobHandler{announcekey.NewJobHandler(keyStore, keyValidator)},
		reconcilerOpts...,
	)
	handleErr(err, "failed to create reconciler manager")

	go func() {
		if err := reconcilerMgr.Start(context.Background()); err != nil {
			log.Printf("reconciler manager stopped: %v", err)
		}
	}()

	// initialization of keyprocessor manager
	bindings := make(map[model.KeyKind]spec.KeyBinding, len(cfg.KeyBindings))
	for kind, binding := range cfg.KeyBindings {
		bindings[model.KeyKind(kind)] = binding
	}
	kpMgr, err := keyprocessor.NewManager(context.Background(), keyprocessor.ManagerConfig{
		KeyStore:        keyStore,
		KeyVersionStore: keyVersionStore,
		Bindings:        bindings,
		Hierarchy:       cfg.Hierarchy,
	})
	handleErr(err, "failed to create key processor manager")

	var grpcOpts []grpc.ServerOption
	if cfg.Server.TLS != nil {
		authn, err := interceptor.NewAuthenticator(cfg.Authentication.AllowedCNs)
		handleErr(err, "failed to create authenticator for gRPC server")
		grpcOpts = append(grpcOpts, grpc.UnaryInterceptor(authn.UnaryInterceptor))

		tlsConfig, err := cfg.Server.TLS.BuildTLSConfig()
		handleErr(err, "failed to build TLS config for gRPC server")
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// gRPC server setup for admin API
	grpcServer := grpc.NewServer(grpcOpts...)
	admin.RegisterTenantServiceServer(grpcServer, admin.NewTenantService(tenantStore))

	// gRPC server setup for agent API
	agents.RegisterServiceServer(grpcServer, agents.NewAgentService(agentStore, *cfg))

	// gRPC server setup for keys API
	keypb.RegisterKeyServiceServer(grpcServer, keypb.NewKeyService(cfg.Name, transactor, keyStore, keyVersionStore, keyValidator, reconcilerMgr, kpMgr))

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

	// KMIP server (optional) — serves unwrapped DEKs to KMIP clients over mTLS.
	var kmipSrv *kmip.Server
	if cfg.KMIP != nil {
		kmipSrv, err = kmip.NewServer(*cfg.KMIP, kpMgr)
		handleErr(err, "failed to create kmip server")
		go func() {
			log.Printf("KMIP server listening on %s", kmipSrv.Addr())
			if err := kmipSrv.Serve(); err != nil {
				log.Printf("KMIP server stopped: %v", err)
			}
		}()
	}

	// graceful shutdown on SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	log.Println("Received shutdown signal, stopping server...")
	grpcServer.GracefulStop()
	if kmipSrv != nil {
		if err := kmipSrv.Shutdown(); err != nil {
			log.Printf("kmip shutdown: %v", err)
		}
	}
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
