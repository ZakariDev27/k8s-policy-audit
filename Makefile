.PHONY: install test lint demo e2e

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

demo:
	-kpaudit scan demo/insecure --min-severity high
	kpaudit scan demo/hardened
	@for f in demo/walkthrough/*.yaml; do printf '%s: ' $$f; kpaudit scan $$f --fail-on never | tail -1; done

# Needs a throwaway cluster as the current kubectl context (see scripts/e2e.sh).
e2e:
	scripts/e2e.sh
