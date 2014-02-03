.PHONY: test cover
test:
	go test -v .

cover:
	go get code.google.com/p/go.tools/cmd/cover
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out
