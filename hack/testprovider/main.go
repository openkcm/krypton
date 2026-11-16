package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	providergrpc "github.com/openkcm/krypton/pkg/api/v1/proto/test/provider"
)

func main() {
	// TODO: Consider evolving this helper into a dedicated `kr-test` command for
	// structured provider setup, rotation, cleanup, and other test workflows.
	server := flag.String("server", "localhost:8080", "root gRPC server address")
	instanceID := flag.String("instance-id", "test-instance", "test-provider instance ID")
	keyID := flag.String("key-id", "test-key", "test-provider key ID")
	accessToken := flag.String("access-token", "test-token", "test-provider access token")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(
		*server,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("connect to root: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := providergrpc.NewServiceClient(conn)
	if _, err := client.UpsertInstance(ctx, &providergrpc.UpsertInstanceRequest{
		InstanceId: *instanceID,
	}); err != nil {
		log.Fatalf("upsert test-provider instance: %v", err)
	}
	if _, err := client.UpsertKey(ctx, &providergrpc.UpsertKeyRequest{
		InstanceId: *instanceID,
		KeyId:      *keyID,
	}); err != nil {
		log.Fatalf("upsert test-provider key: %v", err)
	}
	if _, err := client.UpsertKeyAuth(ctx, &providergrpc.UpsertKeyAuthRequest{
		InstanceId:  *instanceID,
		KeyId:       *keyID,
		AccessToken: *accessToken,
	}); err != nil {
		log.Fatalf("upsert test-provider authentication: %v", err)
	}

	fmt.Printf(`Test provider ready.

instance ID:  %s
key ID:       %s
access token: %s

Bind with:
kr yok bind test-provider --key-id <KRYPTON_ROOT_KEY_ID> --instance-id %s --provider-key-id %s --access-token %s --server %s
`, *instanceID, *keyID, *accessToken, *instanceID, *keyID, *accessToken, *server)
}
