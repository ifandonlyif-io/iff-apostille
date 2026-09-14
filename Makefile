.PHONY: check modules core web sdk apostille-sdk-test apostille-local-test apostille-build verifier security

check: modules core web sdk apostille-local-test verifier

modules:
	@for module in . apostille/zkbudget cmd/apostille; do \
		GOWORK=off go -C "$$module" mod verify || exit; \
	done
	sh scripts/check-apostille-module-isolation.sh

core:
	GOWORK=off go build ./...
	GOWORK=off go vet ./...
	GOWORK=off go test -race ./...

web:
	node --test web/apostille-core.test.mjs web/apostille-erc8004.test.mjs web/apostille-ui.test.mjs

sdk:
	npm --prefix sdk/apostille-js ci --ignore-scripts --no-audit --no-fund
	npm --prefix sdk/apostille-js run build
	npm --prefix sdk/apostille-js run typecheck
	npm --prefix sdk/apostille-js test

apostille-sdk-test: core web sdk

apostille-local-test:
	@for module in apostille/zkbudget cmd/apostille; do \
		GOWORK=off go -C "$$module" build ./... && \
		GOWORK=off go -C "$$module" vet ./... && \
		GOWORK=off go -C "$$module" test -race ./... || exit; \
	done

apostille-build:
	GOWORK=off go -C cmd/apostille build -trimpath -buildvcs=false -o ../../bin/apostille .

verifier:
	python3 scripts/build-verifier.py

security:
	@for module in . apostille/zkbudget cmd/apostille; do \
		GOWORK=off go -C "$$module" run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./... || exit; \
	done
