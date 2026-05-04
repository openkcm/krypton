package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
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

	conn, err := grpc.NewClient(
		cfg.KryptonRoot.Address.URL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	handleErr(err, "failed to connect to root server")
	defer conn.Close()

	agentsCli := agents.NewAgentServiceClient(conn)

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
		_, err := agentsCli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			InstanceId: agentID,
			AgentName:  cfg.Name,
		})
		return err
	})

	handleErr(err, "failed to create heartbeat worker")
	go wrkr.Start(ctx)

	// graceful shutdown on SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	fmt.Println("Received termination signal, shutting down...")
	wrkr.Stop()

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
	cfg, err := config.LoadAgentBootstrapConfig(os.Getenv("AGENT_BOOTSTRAP_CONFIG_PATH"))
	if err != nil {
		port := os.Getenv("ROOT_SERVER_PORT")
		if port == "" {
			port = "8080"
		}
		_, err := strconv.Atoi(port)
		handleErr(err, "invalid ROOT_SERVER_PORT")

		return &config.AgentBootstrapConfig{
			Name: "agent-k1",
			Role: spec.DefaultRole,
			KryptonRoot: config.KryptonRoot{
				Address: config.Address{
					Type: config.AddressTypeGRPC,
					URL:  "localhost:" + port,
				},
			},
		}
	}

	return cfg
}
