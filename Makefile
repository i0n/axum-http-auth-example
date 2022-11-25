SHELL := /bin/bash
NAME := axum-http-auth-example
CONTAINER_NAME := i0nw/${NAME}

all: build
check: fmt build test

POSTGRES_HOST := 0.0.0.0
POSTGRES_DB := axum-http-auth-example
POSTGRES_USER := postgres
POSTGRES_PASSWORD := password

DOCKER_NETWORK := $(shell docker network ls --filter name=${NAME} -q)

print-version: version
	@echo $(VERSION)

print-rev:
	@echo $(REV)

print-branch:
	@echo $(BRANCH)

print-build-date:
	@echo $(BUILD_DATE)

print-build-user:
	@echo $(BUILD_USER)

docker-create-network:
ifeq ($(strip $(DOCKER_NETWORK)),)
	@echo Creating docker network ${NAME}...
	docker network create ${NAME}
else
	@echo Docker network ${NAME} already created.
endif

docker-run: docker-create-network
	docker run --name ${NAME} --rm --network ${NAME} -e REDIS_HOST=redis -e POSTGRES_HOST=timescaledb -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} -p 8000:8000 ${CONTAINER_NAME}:latest

docker-run-postgres: docker-create-network
	docker run --rm --name postgres --network ${NAME} -p 5432:5432 -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} -e POSTGRES_DB=${POSTGRES_DB} -v $(shell pwd)/db/:/docker-entrypoint-initdb.d/ postgres:latest

docker-run-redis: docker-create-network
	docker run --rm -p 6379:6379 --name redis --network ${NAME} redis:latest

docker-run-psql-dev:
	docker exec -it postgres psql -U ${POSTGRES_USER} ${POSTGRES_DB}

clean:
	rm -rf target

# This will stop make linking directories with these names to make commands
.PHONY: all test clean
