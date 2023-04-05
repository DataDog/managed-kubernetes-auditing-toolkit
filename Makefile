all:
	go build -o mkat ./cmd/managed-kubernetes-auditing-toolkit/main.go

test:
	go test ./... -v
