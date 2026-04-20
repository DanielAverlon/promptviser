include .project/gomod-project.mk

SHA := $(shell git rev-parse HEAD)

export PROMPTVISER_JWT_SEED=testseed
export PROMPTVISER_DP_SEED=testseed
export PROMPTVISER_GITHUB_CLIENT_ID=testclientid
export PROMPTVISER_GITHUB_CLIENT_SECRET=testclientsecret

export COVERAGE_EXCLUSIONS="tests|third_party|api/pb/|main\.go|testsuite\.go|mocks\.go|\.pb\.go|\.gen\.go"
export PROMPTVISER_DIR=${PROJ_ROOT}
BUILD_FLAGS=

.PHONY: *

.SILENT:

default: help

all: clean folders tools generate version change_log gen_test_certs start-localstack drop-sql start-sql build dry-run test

#
# clean produced files
#
clean:
	echo "Running clean"
	go clean
	rm -rf \
		/tmp/promptviser \
		./bin \
		./.gopath \
		${COVPATH} \

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.1
	go install github.com/effective-security/cov-report/cmd/cov-report@latest
	go install github.com/effective-security/xpki/cmd/hsm-tool@latest
	go install github.com/effective-security/xpki/cmd/xpki-tool@latest
	go install github.com/effective-security/xdb/cmd/xdbcli@latest
	go install github.com/itchyny/gojq/cmd/gojq@latest
	go install go.uber.org/mock/mockgen@latest

folders:
	mkdir -p /tmp/promptviser/certs \
		/tmp/promptviser/logs
	chmod -R 0700 /tmp/promptviser

version:
	echo "*** building version $(GIT_VERSION)"
	gofmt -r '"GIT_VERSION" -> "$(GIT_VERSION)"' api/version/current.template > api/version/current.go

build_promptviser:
	echo "*** Building promptviser"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/promptviser ./cmd/promptviser

build_promptviserctl:
	echo "*** Building promptviserctl"
	# go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/promptviserctl ./cmd/promptviserctl

build: build_promptviser build_promptviserctl

dry-run:
	echo "*** starting dry-run"
	${PROJ_ROOT}/bin/promptviser --dry-run 2>/dev/null
	echo "*** dry-run completed"

change_log:
	echo "Recent changes" > ./change_log.txt
	echo "Build Version: $(GIT_VERSION)" >> ./change_log.txt
	echo "Commit: $(GIT_HASH)" >> ./change_log.txt
	echo "==================================" >> ./change_log.txt
	git log -n 20 --pretty=oneline --abbrev-commit >> ./change_log.txt

commit_version:
	git add .; git commit -m "Updated version"

trusty_root:
	mkdir -p /tmp/promptviser/certs
	tar -xzvf $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.key.tar.gz -C $(PROJ_ROOT)/etc/dev/certs/root/
	cp $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem /tmp/promptviser/certs/trusty_root_ca.pem

gen_test_certs: trusty_root
	echo "*** Running gen_test_certs"
	echo "*** generating test CAs"
	$(PROJ_ROOT)/.project/gen_certs.sh \
		--hsm-config inmem \
		--ca-config $(PROJ_ROOT)/etc/dev/certs/ca-config.bootstrap.yaml \
		--output-dir /tmp/promptviser/certs \
		--csr-dir $(PROJ_ROOT)/etc/dev/certs/csr_profile \
		--csr-prefix promptviser_ \
		--out-prefix promptviser_ \
		--key-label test_ \
		--root-ca $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem \
		--root-ca-key $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.key \
		--ca1 --ca2  --bundle --server --peer --client --force

start-localstack:
	echo "*** starting localstack"
	# we need re-create /tmp/promptviser/localstack folder with certs
	rm -rf /tmp/promptviser/localstack
	mkdir -p /tmp/promptviser/localstack
	cp $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem /tmp/promptviser/certs/promptviser_peer.* /tmp/promptviser/localstack
	chmod 644 /tmp/promptviser/localstack/*
	#
	docker compose -f docker-compose.promptviser.yml -p promptviser up -d --force-recreate --remove-orphans

start-sql:
	echo "*** creating SQL tables "
	$(PROJ_ROOT)/sql/adviserdb/wait_sql.sh localhost 25432 postgres postgres
	docker exec -e 'PGPASSWORD=postgres' promptviser-sql-1 psql -h localhost -p 25432 -U postgres -a -f /promptviser_sql/adviserdb/create_local_db.sql
	docker exec -e 'PGPASSWORD=postgres' promptviser-sql-1 psql -h localhost -p 25432 -U postgres -lqt
	# escape password for postgres
	echo "postgres://promptviser:promptviser%3Flocal%23%26@localhost:25432?sslmode=disable&dbname=adviserdb" > etc/dev/sql-conn-adviserdb.txt

drop-sql:
	echo "*** dropping SQL tables "
	$(PROJ_ROOT)/sql/adviserdb/wait_sql.sh localhost 25432 postgres postgres
	docker exec -e 'PGPASSWORD=postgres' promptviser-sql-1 psql -h localhost -p 25432 -U postgres -a -f /promptviser_sql/adviserdb/drop_local_db.sql
	docker exec -e 'PGPASSWORD=postgres' promptviser-sql-1 psql -h localhost -p 25432 -U postgres -lqt

gen-sql-schema: dry-run
	echo "*** generating SQL schema"
	echo "\`\`\`" > internal/db/adviserdb/README.md && \
	bin/xdbcli --sql-source=file://etc/dev/sql-conn-adviserdb.txt \
		schema columns --dependencies --db adviserdb >> internal/db/adviserdb/README.md && \
	echo "\`\`\`" >> internal/db/adviserdb/README.md
	rm -f ./internal/db/adviserdb/model/*.gen.go ./internal/db/adviserdb/schema/*.gen.go
	bin/xdbcli --sql-source=file://etc/dev/sql-conn-adviserdb.txt \
		schema generate --db adviserdb \
		--types-def internal/db/adviserdb/schema/typesmap.yaml \
		--imports github.com/effective-security/promptviser/api/pb \
		--dependencies \
		--out-model internal/db/adviserdb/model \
		--out-schema internal/db/adviserdb/schema
	goimports -w ./internal/db/adviserdb/model/*.gen.go ./internal/db/adviserdb/schema/*.gen.go

docker: change_log
	docker build --no-cache -f Dockerfile -t effectivesecurity/promptviser:main .

docker-push: docker
	[ ! -z ${DOCKER_PASSWORD} ] && echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin || echo "skipping docker login"
	docker push effectivesecurity/promptviser:main
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effectivesecurity/promptviser:${DOCKER_NUMBER} || echo "skipping docker version, pushing latest only"

docker-citest:
	cd ./scripts/integration && ./setup.sh

proto:
	echo "*** building public proto in $(PROJ_ROOT)/api/pb"
	mkdir -p ./api/pb/mockpb ./api/pb/openapi ./api/pb/proxypb
	docker run --rm \
		-v $(PROJ_ROOT)/api/pb:/dirs \
		-v $(PROJ_ROOT)/api/pb/third_party:/third_party \
		--name protoc-gen-go \
		effectivesecurity/protoc-gen-go:sha-021a3d3 \
		--i "-I /third_party" \
		--dirs /dirs/protos \
		--golang ./.. \
		--enum pb ./.. \
		--json ./.. \
		--mock ./.. \
		--proxy ./.. \
		--methods ./.. \
		--oapi output_mode=source_relative,naming=proto:./../openapi
	echo "Changing owner for generated files. Please enter your sudo creds"
	sudo chown -R $(USER) ./api/pb
	goimports -l -w ./api/pb
	gofmt -s -l -w -r 'interface{} -> any' ./api/pb
	# remove empty generated openapi files without any service
	rm -rf ./api/pb/openapi/types.openapi.yaml
