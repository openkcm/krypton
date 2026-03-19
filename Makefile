.PHONY: clean
clean:
	rm -f cover.out cover.html krypton
	rm -rf cover/

.PHONY: lint
lint:
	golangci-lint run --fix ./...


.PHONY: test
test: clean
	@mkdir -p cover/integration cover/unit
	@go clean -testcache

	go test -count=1 -race -cover ./... -args -test.gocoverdir="${PWD}/cover/unit"
	GOCOVERDIR="${PWD}/cover/integration" go test -count=1 -race ./integration

	@go tool covdata textfmt -i=./cover/unit,./cover/integration -o cover.out

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

.PHONY: server
server:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/server

.PHONY: dev
dev: postgres server
