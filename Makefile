BINARY_NAME=gateway

build:
	go build -o ./bin/${BINARY_NAME}

run:
	go build -o ./bin/${BINARY_NAME}
	./bin/${BINARY_NAME}

deps:
	go mod download