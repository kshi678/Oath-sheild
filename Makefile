.PHONY: tidy run build test vet up down secrets

tidy:
	go mod tidy

run:
	go run ./cmd/server

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/goauth ./cmd/server

test:
	go test ./... -race -count=1

vet:
	go vet ./...

up:
	docker compose up --build -d

down:
	docker compose down

secrets:
	@echo "JWT_ACCESS_SECRET=$$(openssl rand -base64 48 | tr -d '\n')"
	@echo "JWT_REFRESH_SECRET=$$(openssl rand -base64 48 | tr -d '\n')"
