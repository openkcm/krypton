package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/worker"
	"github.com/openkcm/krypton/pkg/api/agents"
)

// This is a simple agent that registers itself with the root server,
// sends periodic heartbeats, and deregisters on shutdown.
func main() {
	rootSrvPort := os.Getenv("ROOT_SERVER_PORT")
	if rootSrvPort == "" {
		rootSrvPort = ":8080"
	}

	agentName := os.Getenv("AGENT_NAME")
	if agentName == "" {
		agentName = "agent-k1"
	}

	agentID := os.Getenv("AGENT_ID")
	if agentID == "" {
		agentID = uuid.New().String()
	}

	agentClient, err := agents.NewClient("http://localhost"+rootSrvPort, agentName, agentID)
	handleErr(err, "failed to create agent client")

	// Example usage: register the agent
	registerResp, err := agentClient.Register(context.Background(), agents.RegisterRequest{})
	handleErr(err, "failed to register agent")

	keepAliveInterval := time.Duration(registerResp.Config.KeepAlive) * time.Second
	wrkr, err := worker.New(keepAliveInterval, func(ctx context.Context) error {
		_, err := agentClient.SendHeartbeat(ctx, agents.SendHeartbeatRequest{})
		return err
	})

	handleErr(err, "failed to create heartbeat worker")
	go wrkr.Start(context.Background())

	// graceful shutdown on SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	<-signalChan
	wrkr.Stop()

	_, err = agentClient.Deregister(context.Background(), agents.DeregisterRequest{})
	if err != nil {
		log.Printf("failed to deregister agent: %v", err)
	}

	fmt.Println("Received termination signal, shutting down...")
}

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
