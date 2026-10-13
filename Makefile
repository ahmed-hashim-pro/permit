# Thin wrappers over npm, plus the targets that regenerate what the README shows.
.PHONY: build test lint check examples demo clean

build:
	npm run build

test:
	npm test

lint:
	npm run lint

check: lint test

# Rewrite examples/*/before.json and after.json from scripts/examples.py.
examples:
	python3 scripts/examples.py

# Re-record docs/demo.gif from the real CLI (needs Docker for VHS).
# The VHS image is Debian bookworm; the host's own node is mounted into it.
NODE_HOME := $(abspath $(dir $(shell command -v node))..)
demo: build
	docker run --rm -u $$(id -u):$$(id -g) -e HOME=/tmp -v $(CURDIR):/vhs -v $(NODE_HOME):/opt/node:ro \
	  ghcr.io/charmbracelet/vhs:v0.10.0 docs/demo.tape

clean:
	rm -rf dist
