.PHONY: build run clean provision
# Build the backend binary
build:
	go build -o flaregate .

# Run the application
run: build
	PORT=8025 ./flaregate

# NAT VPS helper: create/update Cloudflare Tunnel + DNS in one go
provision:
	python3 scripts/flaregate-provision.py

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f flaregate