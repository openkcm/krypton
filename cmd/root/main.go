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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	_ "github.com/lib/pq"

	orbitalstore "github.com/openkcm/orbital/store/sql"

	"github.com/openkcm/krypton/internal/agentclient"
	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/internal/interceptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	jobspb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/jobs"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
	"github.com/openkcm/krypton/pkg/validator"
)

// Simple krypton server for manual testing and development.
// Not intended for production use (yet).
func main() {
	err := securemem.NoDump()
	handleErr(err, "failed to set no-dump for secure memory")

	srvPort := os.Getenv("SERVER_PORT")
	if srvPort == "" {
		srvPort = "8080"
	}
	_, err = strconv.Atoi(srvPort)
	handleErr(err, "invalid SERVER_PORT value")

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dsn)
	handleErr(err, "failed to connect to database")
	defer db.Close()

	// run migrations
	err = storesql.Migrate(context.Background(), db, storesql.Root)
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

	// orbital repository, shared by root's single embedded orchestrator.
	orbitalStore, err := orbitalstore.New(context.Background(), db)
	handleErr(err, "failed to create orbital store")
	repo := orbital.NewRepository(orbitalStore)

	// mTLS clients to agents, keyed by name — used by the embedded announce and
	// activate task handlers to reach agents over gRPC.
	var authConfig config.AuthConfig
	if cfg.Auth != nil {
		authConfig = cfg.Auth.Config
	}
	agentClients, err := agentclient.New(cfg.Connections, authConfig)
	handleErr(err, "failed to create agent client registry")

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

	// Root's single embedded orbital orchestrator. All tasks run in-process on
	// root (the local target); announce and activate reach agents over gRPC.
	localTarget := orchestrator.DefaultLocalTargetName
	orchHandlers := orchestrator.Handlers{
		Jobs: []orchestrator.JobHandler{
			announcekey.NewJobHandler(keyStore, keyValidator, localTarget),
			activatekey.NewJobHandler(keyStore, localTarget),
		},
		Groups: []orchestrator.JobGroupHandler{
			activatekey.NewJobGroupHandler(),
		},
		Tasks: []orchestrator.TaskHandler{
			announcekey.NewTaskHandler(agentClients),
			activatekey.NewTaskHandler(cfg.Name, transactor, keyStore, keyVersionStore, kpMgr, agentClients),
		},
	}

	var orchOpts []orchestrator.Option
	if cfg.Reconciler.ExecInterval > 0 {
		orchOpts = append(orchOpts, orchestrator.WithExecInterval(cfg.Reconciler.ExecInterval))
	}
	if cfg.Reconciler.MaxReconcileCount > 0 {
		orchOpts = append(orchOpts, orchestrator.WithMaxPendingReconciles(cfg.Reconciler.MaxReconcileCount))
	}

	orch, err := orchestrator.New(context.Background(), repo, orchHandlers, orchOpts...)
	handleErr(err, "failed to create orchestrator")

	go func() {
		if err := orch.Start(context.Background()); err != nil {
			log.Printf("orchestrator stopped: %v", err)
		}
	}()

	var grpcOpts []grpc.ServerOption
	if cfg.Auth != nil {
		mtlsConfig, err := config.GetAuthConfig(cfg.Auth.Config)
		handleErr(err, "failed to get auth config for gRPC server")

		authn, err := interceptor.NewAuthenticator(cfg.Auth.IdentityConfigs.URIs())
		handleErr(err, "failed to create authenticator for gRPC server")
		grpcOpts = append(grpcOpts, grpc.UnaryInterceptor(authn.UnaryInterceptor))

		tlsConfig, err := mtlsConfig.Server.BuildTLSConfig()
		handleErr(err, "failed to build TLS config for gRPC server")
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// gRPC server setup for admin API
	grpcServer := grpc.NewServer(grpcOpts...)
	admin.RegisterTenantServiceServer(grpcServer, admin.NewTenantService(tenantStore))

	// gRPC server setup for agent API
	agents.RegisterServiceServer(grpcServer, agents.NewAgentService(agentStore, *cfg))

	// gRPC server setup for keys API
	keypb.RegisterKeyServiceServer(grpcServer, keypb.NewKeyService(cfg.Name, transactor, keyStore, keyVersionStore, keyValidator, orch, kpMgr))

	// gRPC server setup for job status API
	jobspb.RegisterJobServiceServer(grpcServer, jobspb.NewJobService(orch))

	// gRPC sealer service — lets agent-managed keys seal their material against
	// root's key processor over the RPCManager transport.
	sealer.RegisterServiceServer(grpcServer, sealer.NewSealerService(kpMgr))

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
	_ = orch.Stop(context.Background())
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
			HeartbeatThreshold: time.Second * 120,
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
