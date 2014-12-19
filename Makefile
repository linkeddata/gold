.PHONY: test cover
test:
	go get golang.org/x/tools/cmd/cover
	go test -cover -v .

bench:
	@go test -bench . -benchmem

cover:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out
