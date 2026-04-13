BIN_DIR := bin
SERVER  := $(BIN_DIR)/server
CLIENT  := $(BIN_DIR)/client

.PHONY: all build server client run-server clean tidy lint 

all: build

build: server client

server:
	go build -o $(SERVER) ./cmd/server

client:
	go build -o $(CLIENT) ./cmd/client

run-server: server
	@[ -f .env ] && . ./.env; ./$(SERVER)

tidy:
	go mod tidy

lint:
	go vet ./...

clean:
	rm -rf $(BIN_DIR)
