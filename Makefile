# Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
BIN=goproxy
VERSION=2.8.1
LDFLAGS=-s -w -X main.Version=$(VERSION)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) .
build-windows:
	mkdir -p dist && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS) -H=windowsgui" -o dist/$(BIN).exe .
# sign: release signature (keys/ is private and never shipped; the public key is in signing.go)
sign-windows: build-windows
	go run ./cmd/sign -key keys/release-ed25519.key dist/$(BIN).exe
zip-windows: sign-windows
	cd dist && rm -f goproxy-dns-v$(VERSION)-windows.zip && python3 -c "import zipfile,sys;z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED,compresslevel=9);[z.write(f) for f in sys.argv[2:]];z.close()" goproxy-dns-v$(VERSION)-windows.zip goproxy.exe goproxy.exe.sig README-WINDOWS.txt install-service.cmd uninstall-service.cmd
run: build
	sudo ./$(BIN) -dns-addr :53 -http-addr :8080 -cache-gb 4
test:
	go vet ./... && go test -count=1 -v ./...
bench:
	go test -run TestHitLatency -bench . -benchmem -v ./...
install: build
	sudo install -m755 $(BIN) /usr/local/bin/$(BIN)
	sudo install -m644 goproxy.service /etc/systemd/system/goproxy.service
	sudo systemctl daemon-reload && sudo systemctl enable --now goproxy
.PHONY: build build-windows sign-windows zip-windows run test bench install
