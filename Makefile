export GOEXPERIMENT := runtimesecret

.PHONY: clean
clean:
	rm -f cover.out cover.html krypton
	rm -rf cover/

.PHONY: lint
lint:
	golangci-lint run --fix ./...


.PHONY: test
test: clean
	@mkdir -p cover/integration-cli cover/integration-test cover/unit
	@go clean -testcache

	go test -count=1 -race -cover ./... -args -test.gocoverdir="${PWD}/cover/unit"
	CLI_GOCOVERDIR="${PWD}/cover/integration-cli" go test -count=1 -race -cover -coverpkg=./... ./integration -args -test.gocoverdir="${PWD}/cover/integration-test"

	@go tool covdata textfmt -i=./cover/unit,./cover/integration-test,./cover/integration-cli -o cover.out

	@echo "On a Mac, you can use the following command to open the coverage report in the browser\ngo tool cover -html=cover.out -o cover.html && open cover.html"

CLI_TOOL_NAME := kr

.PHONY: cli
cli:
	@go build -o $(CLI_TOOL_NAME) ./cli
	@mv $(CLI_TOOL_NAME) $(shell go env GOPATH)/bin/
	@echo "use $(CLI_TOOL_NAME) to interact with krypton"

# Development targets for manual testing
POSTGRES_CONTAINER := krypton-postgres
POSTGRES_PORT := 5432
POSTGRES_USER := krypton
POSTGRES_PASSWORD := krypton
POSTGRES_DB := krypton
DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=disable

.PHONY: postgres
postgres:
	@docker rm -f $(POSTGRES_CONTAINER) 2>/dev/null || true
	docker run -d --name $(POSTGRES_CONTAINER) \
		-e POSTGRES_USER=$(POSTGRES_USER) \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		-e POSTGRES_DB=$(POSTGRES_DB) \
		-p $(POSTGRES_PORT):5432 \
		postgres:18-alpine
	@echo "Waiting for postgres to be ready..."
	@timeout=30; \
	while ! docker exec $(POSTGRES_CONTAINER) pg_isready -U $(POSTGRES_USER) -d $(POSTGRES_DB) > /dev/null 2>&1; do \
		timeout=$$((timeout - 1)); \
		if [ $$timeout -le 0 ]; then \
			echo "Postgres failed to start"; \
			exit 1; \
		fi; \
		sleep 1; \
	done
	@echo "Postgres is ready at localhost:$(POSTGRES_PORT)"

.PHONY: postgres-stop
postgres-stop:
	docker rm -f $(POSTGRES_CONTAINER) 2>/dev/null || true

ROOT_SERVER_PORT := 8080

.PHONY: agent
agent:
	ROOT_SERVER_PORT="$(ROOT_SERVER_PORT)" go run ./cmd/agent

.PHONY: root
root:
	SERVER_PORT="$(ROOT_SERVER_PORT)" DATABASE_URL="$(DATABASE_URL)" go run ./cmd/root

.PHONY: dev
dev: postgres root

.PHONY: proto-gen
proto-gen:
	 ./scripts/proto-gen.sh "api-specs/v1/proto/agents"
	$(MAKE) go-format

.PHONY: go-format
go-format:
	goimports -w .
	gofmt -s -w .
