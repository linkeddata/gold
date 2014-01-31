.PHONY: all cover
all:

cover:
	go get code.google.com/p/go.tools/cmd/cover
	go test -covermode=count -coverprofile=coverage.out
	go tool cover -html=coverage.out
