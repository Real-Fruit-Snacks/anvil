DIST := dist

.PHONY: build build-all build-linux build-windows windows-resource test vet fmt clean
.PHONY: env-up env-down env-logs e2e

build:
	CGO_ENABLED=0 go build -o anvil ./cmd/anvil

build-all: build-linux build-windows

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(DIST)/anvil-linux-amd64 ./cmd/anvil

build-windows: windows-resource
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(DIST)/anvil-windows-amd64.exe ./cmd/anvil

# Generates cmd/anvil/resource_windows_amd64.syso (version info + manifest).
# The _windows_amd64 suffix means only windows/amd64 builds link it.
windows-resource:
	cd cmd/anvil && go tool goversioninfo -o resource_windows_amd64.syso -manifest ../../anvil.manifest ../../versioninfo.json

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -f anvil anvil.exe
	rm -f cmd/anvil/*.syso
	rm -rf $(DIST)

# --- Docker test lab (Samba AD DC) ---
# Git Bash users may need Docker's bin dir on PATH first:
#   export PATH="$PATH:/c/Program Files/Docker/Docker/resources/bin"

env-up:
	docker compose up -d dc

env-down:
	docker compose down -v

env-logs:
	docker compose logs -f dc

e2e: build-linux testenv/bin/getTGT-linux-amd64
	docker compose --profile e2e run --rm runner

# getTGT is built from the gopacket dependency (tools/getTGT) so the runner
# can mint a ccache against the lab KDC.
testenv/bin/getTGT-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $@ github.com/mandiant/gopacket/tools/getTGT
