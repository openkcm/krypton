package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"uuid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/tenants"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
	"github.com/openkcm/krypton/pkg/model"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// This is a simple agent that registers itself with the root server,
// sends periodic heartbeats, and deregisters on shutdown.
func main() {
	err := securemem.NoDump()
	handleErr(err, "failed to set no-dump for secure memory")

	ctx := context.Background()

	agentID := os.Getenv("AGENT_ID")
	if agentID == "" {
		agentID = uuid.New().String()
	}

	cfg := loadConfig()

	grpcOpts := rootGRPCOpts(cfg)

	conn, err := grpc.NewClient(
		cfg.KryptonRoot.Address.URL,
		grpcOpts...,
	)
	handleErr(err, "failed to connect to root server")
	defer conn.Close()

	agentsCli := agents.NewServiceClient(conn)

	// Example usage: register the agent
	log.Printf("Registering agent %s with ID %s", cfg.Name, agentID)
	reg, err := agentsCli.Register(ctx, &agents.RegisterAgentRequest{
		AgentName:  cfg.Name,
		InstanceId: agentID,
	})
	handleErr(err, "failed to register agent")

	agentCfg, err := config.UnmarshalAgentConfig(reg.GetConfig())
	handleErr(err, "failed to unmarshal agent config")

	keepAliveInterval := time.Duration(agentCfg.KeepAlive) * time.Second
	wrkr, err := worker.New(keepAliveInterval, func(ctx context.Context) error {
		log.Printf("Sending heartbeat for agent %s (ID: %s)", cfg.Name, agentID)
		_, err = agentsCli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			InstanceId: agentID,
			AgentName:  cfg.Name,
		})
		return err
	})
	handleErr(err, "failed to create heartbeat worker")
	go wrkr.Start(ctx)

	db := database(ctx)
	defer db.Close()

	kpMgr := keyManager(ctx, db, *agentCfg)
	grpcServer, lis := setupKeyServiceServer(ctx, db, kpMgr)

	log.Println("Starting agent key service listener")
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("agent key service stopped: %v", err)
		}
	}()

	// KMIP server (optional) — serves unwrapped DEKs to KMIP clients over mTLS.
	var kmipSrv *kmip.Server
	if agentCfg.KMIP != nil {
		kmipSrv, err = kmip.NewServer(*agentCfg.KMIP, kpMgr)
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
	fmt.Println("Received termination signal, shutting down...")
	wrkr.Stop()
	grpcServer.GracefulStop()

	log.Println("Deregistering agent...")
	dCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = agentsCli.Deregister(dCtx, &agents.DeregisterAgentRequest{
		InstanceId: agentID,
		AgentName:  cfg.Name,
	})
	if err != nil {
		log.Printf("failed to deregister agent: %v", err)
	}

	if kmipSrv != nil {
		if err := kmipSrv.Shutdown(); err != nil {
			log.Printf("kmip shutdown: %v", err)
		}
	}

	log.Println("Agent shutdown complete")
}

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func loadConfig() *config.AgentBootstrapConfig {
	path := os.Getenv("AGENT_BOOTSTRAP_CONFIG_PATH")
	if path == "" {
		path = "config.yaml"
	}

	cfg, err := config.LoadAgentBootstrapConfig(path)
	handleErr(err, "failed to load agent config from "+path)

	if portOverride := os.Getenv("ROOT_SERVER_PORT"); portOverride != "" {
		_, err := strconv.Atoi(portOverride)
		handleErr(err, "invalid ROOT_SERVER_PORT")
		cfg.KryptonRoot.Address.URL = "127.0.0.1:" + portOverride
	}

	return cfg
}

func setupKeyServiceServer(ctx context.Context, db *sql.DB, kpMgr *keyprocessor.Manager) (*grpc.Server, net.Listener) {
	tr := storesql.NewTransactor(db)

	port := os.Getenv("AGENT_PORT")
	if port == "" {
		port = "9091"
	}

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ":"+port)
	handleErr(err, "failed to listen on agent port")

	srv := grpc.NewServer(
		// this is required to ensure that sensitive data in the RPC context is cleaned up after each RPC call
		grpc.StatsHandler(securemem.NewRPCHandler()),
	)

	keys.RegisterKeyServiceServer(srv, keys.NewKeyService(tr))
	keyversions.RegisterKeyVersionServiceServer(srv, keyversions.NewService(tr, kpMgr))
	tenants.RegisterTenantServiceServer(srv, tenants.NewTenantService(tr))
	sealer.RegisterServiceServer(srv, sealer.NewSealerService(kpMgr))

	log.Printf("agent key service listening on :%s", port)
	return srv, lis
}

func database(ctx context.Context) *sql.DB {
	u := os.Getenv("AGENT_DATABASE_URL")
	if u == "" {
		log.Fatal("AGENT_DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", u)
	handleErr(err, "failed to connect to agent database")

	err = storesql.Migrate(ctx, db, storesql.Agent)
	handleErr(err, "failed to run agent migrations")

	return db
}

func keyManager(ctx context.Context, db *sql.DB, agentCfg config.AgentConfig) *keyprocessor.Manager {
	// TODO: add the MTLS client for the parents,
	// currently it is not propogated in the AgentConfig
	rg, err := grpcconn.NewRegistry(agentCfg.Connections, grpc.WithTransportCredentials(insecure.NewCredentials()))
	handleErr(err, "failed to create grpc connection registry")

	bgs := make(map[model.KeyKind]spec.KeyBinding, len(agentCfg.KeyBindings))
	for kind, binding := range agentCfg.KeyBindings {
		bgs[model.KeyKind(kind)] = binding
	}

	kpMgr, err := keyprocessor.NewManager(context.Background(), keyprocessor.ManagerConfig{
		KeyStore:        storesql.NewKeyStore(db),
		KeyVersionStore: storesql.NewKeyVersionStore(db),
		Bindings:        bgs,
		Hierarchy:       agentCfg.Hierarchy,
		Registry:        rg,
	})
	handleErr(err, "failed to create key processor manager")
	return kpMgr
}

func rootGRPCOpts(c *config.AgentBootstrapConfig) []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if c.Auth != nil {
		mc, err := config.GetAuthConfig(c.Auth.Config)
		handleErr(err, "failed to get auth config")

		tc, err := mc.Client.BuildTLSConfig()
		handleErr(err, "failed to build TLS config")
		opts[0] = grpc.WithTransportCredentials(credentials.NewTLS(tc))
	}
	return opts
}
