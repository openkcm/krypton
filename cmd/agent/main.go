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

	"github.com/google/uuid"
	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/client/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// This is a simple agent that registers itself with the root server,
// sends periodic heartbeats, and deregisters on shutdown.
func main() {
	ctx := context.Background()

	agentID := os.Getenv("AGENT_ID")
	if agentID == "" {
		agentID = uuid.New().String()
	}

	cfg := loadConfig()

	grpcOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if cfg.Client.TLS != nil {
		tlsConf, err := cfg.Client.TLS.BuildTLSConfig()
		handleErr(err, "failed to build TLS config")
		grpcOpts[0] = grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))
	}

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

	agentCfg, err := agents.UnmarshalAgentConfig(reg.GetConfig())
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

	// agent-side operator: own database, rpc.Server, handler registration
	agentDB, rpcServer, operator := setupOperator(ctx)
	defer agentDB.Close()

	log.Println("Starting operator listener")
	go func() {
		if err := operator.ListenAndRespond(ctx); err != nil {
			log.Printf("operator stopped: %v", err)
		}
	}()

	// graceful shutdown on SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	fmt.Println("Received termination signal, shutting down...")
	wrkr.Stop()
	if err := rpcServer.Close(context.Background()); err != nil {
		log.Printf("failed to close rpc server: %v", err)
	}

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

func setupOperator(ctx context.Context) (*sql.DB, *rpc.Server, *orbital.Operator) {
	dsn := os.Getenv("AGENT_DATABASE_URL")
	if dsn == "" {
		log.Fatal("AGENT_DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dsn)
	handleErr(err, "failed to connect to agent database")

	err = storesql.Migrate(ctx, db)
	handleErr(err, "failed to run agent migrations")

	keyStore := storesql.NewKeyStore(db)

	agentPort := os.Getenv("AGENT_PORT")
	if agentPort == "" {
		agentPort = "9091"
	}

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ":"+agentPort)
	handleErr(err, "failed to listen on agent port")

	rpcServer, err := rpc.NewServer(lis)
	handleErr(err, "failed to create rpc server")

	op, err := orbital.NewOperator(orbital.TargetOperator{Client: rpcServer})
	handleErr(err, "failed to create operator")

	err = op.RegisterHandler(announcekey.TaskType, announcekey.NewTaskHandler(keyStore))
	handleErr(err, "failed to register announce-key handler")

	log.Printf("agent operator listening on :%s", agentPort)
	return db, rpcServer, op
}
