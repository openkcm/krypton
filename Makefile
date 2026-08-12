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
	SERVER_PORT="$(ROOT_SERVER_PORT)" DATABASE_URL="$(DATABASE_URL)" ROOT_CONFIG_PATH="./demo/krypton.yaml" KRYPTON_ROOT_KEY=$(KRYPTON_ROOT_KEY) go run ./cmd/root

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
KRYPTON_ROOT_KEY := uHpU0RZgYfgaqtWkrS5G7qunD9P/HWcpxViEK8w/EMo=
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

.PHONY: krypton-down
krypton-down:
	docker compose --file ./demo/compose.yaml down krypton

.PHONY: krypton-up
krypton-up:
	docker compose --file ./demo/compose.yaml up krypton

.PHONY: postgres-down
postgres-down:
	docker compose --file ./demo/compose.yaml down postgres

.PHONY: postgres-up
postgres-up:
	docker compose --file ./demo/compose.yaml up postgres

.PHONY: mongodb1-up
mongodb1-up:
	@mkdir -p ./demo/mongodb1/db ./demo/mongodb1/configdb
	docker compose --file ./demo/compose.yaml up mongodb1

.PHONY: mongodb1-down
mongodb1-down:
	docker compose --file ./demo/compose.yaml down mongodb1

.PHONY: mongodb2-up
mongodb2-up:
	@mkdir -p ./demo/mongodb2/db ./demo/mongodb2/configdb
	docker compose --file ./demo/compose.yaml up mongodb2

.PHONY: mongodb2-down
mongodb2-down:
	docker compose --file ./demo/compose.yaml down mongodb2

TENANT_ID ?= $(shell uuidgen | tr '[:upper:]' '[:lower:]')
CERTS_DIR ?= ./demo/certs

.PHONY: generate-server-certs
generate-server-certs:
	./demo/generate-server-certs.sh "$(CERTS_DIR)"

.PHONY: generate-client-certs
generate-client-certs:
	./demo/generate-client-certs.sh "$(TENANT_ID)" "$(CERTS_DIR)"


.PHONY: cleanup
cleanup:
	@docker compose  --file demo/compose.yaml down
	@rm -rf ./demo/mongodb1/db ./demo/mongodb1/configdb
	@rm -rf ./demo/mongodb2/db ./demo/mongodb2/configdb
	@rm ./demo/k1-vault.db ./demo/k2-vault.db
