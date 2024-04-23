.PHONY: build
build:
	go build -o _output/veth-ethtool

test:
	go test -v -count 1 ./...
