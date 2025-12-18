.PHONY: build run clean

# Build everything (Frontend + Backend)
build:
	go mod tidy
	go build -o flaregate main.go

# Run the application
run: build
	 export PORT=8025 && ./flaregate
# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f flaregate