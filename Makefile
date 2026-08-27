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
	CLI_GOCOVERDIR="${PWD}/cover/integration-cli" go test -p 1 -count=1 -race -cover -coverpkg=./... ./integration -args -test.gocoverdir="${PWD}/cover/integration-test"

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
POSTGRES_DB_AGENT := krypton_agent
DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=disable
AGENT_DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB_AGENT)?sslmode=disable

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
	@docker exec $(POSTGRES_CONTAINER) psql -U $(POSTGRES_USER) -c "CREATE DATABASE $(POSTGRES_DB_AGENT);" || true
	@echo "Postgres is ready at localhost:$(POSTGRES_PORT)"

.PHONY: postgres-stop
postgres-stop:
	docker rm -f $(POSTGRES_CONTAINER) 2>/dev/null || true

ROOT_SERVER_PORT := 8080

.PHONY: agent
agent:
	ROOT_SERVER_PORT="$(ROOT_SERVER_PORT)" AGENT_BOOTSTRAP_CONFIG_PATH="./examples/agent.config.yaml" AGENT_DATABASE_URL="$(AGENT_DATABASE_URL)" go run ./cmd/agent

.PHONY: root
root:
	KRYPTON_ROOT_KEY="$(KRYPTON_ROOT_KEY)" ROOT_CONFIG_PATH="./examples/root.config.yaml" SERVER_PORT="$(ROOT_SERVER_PORT)" DATABASE_URL="$(DATABASE_URL)" go run ./cmd/root

.PHONY: dev
dev: postgres root

.PHONY: proto-gen
proto-gen:
	./scripts/proto-gen.sh "api-specs/v1/proto/agents"
	./scripts/proto-gen.sh "api-specs/v1/proto/admin"
	./scripts/proto-gen.sh "api-specs/v1/proto/admin/keys"
	./scripts/proto-gen.sh "api-specs/v1/proto"
	$(MAKE) go-format

.PHONY: go-format
go-format:
	goimports -w .
	gofmt -s -w .

.PHONY: helm-lint
helm-lint:
	helm lint ./charts/root

.PHONY: helm-template
helm-template:
	helm template krypton-root ./charts/root

ROOT_HELM_RELEASE := krypton-root
ROOT_IMAGE := krypton-root:local
KRYPTON_ROOT_KEY := $(shell openssl rand -base64 32)
ROOT_DATABASE_URL := postgres://krypton:krypton@krypton-root-postgres:5432/krypton?sslmode=disable

.PHONY: root-build
root-build:
	docker build -f cmd/root/Dockerfile -t $(ROOT_IMAGE) .

.PHONY: root-deploy
root-deploy: root-build deploy-postgres
	$(IMAGE_LOAD)
	helm upgrade --install $(ROOT_HELM_RELEASE) ./charts/root \
		--set image.registry="" \
		--set image.repository=krypton-root \
		--set image.tag=local \
		--set image.pullPolicy=IfNotPresent \
		--set-json 'image.pullSecrets=[]' \
		--set-json 'extraEnvs=[{"name":"KRYPTON_ROOT_KEY","value":"$(KRYPTON_ROOT_KEY)"},{"name":"DATABASE_URL","value":"$(ROOT_DATABASE_URL)"}]'

.PHONY: root-undeploy
root-undeploy:
	helm uninstall $(ROOT_HELM_RELEASE)

CLUSTER := krypton
# IMAGE_LOAD ?= kind load docker-image $(ROOT_IMAGE)
# IMAGE_LOAD ?= minikube image load $(ROOT_IMAGE)
# IMAGE_LOAD ?= true  # Docker Desktop (no-op, shared daemon)
IMAGE_LOAD ?= k3d image import $(ROOT_IMAGE) --cluster $(CLUSTER)

.PHONY: k3d-cluster
k3d-cluster:
	@k3d cluster list $(CLUSTER) >/dev/null 2>&1 || \
		k3d cluster create $(CLUSTER)

.PHONY: deploy-postgres
deploy-postgres:
	kubectl apply -f hack/postgres.yaml

