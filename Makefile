.PHONY: install test lint demo e2e

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

demo:
	-kpaudit scan demo/insecure
	kpaudit scan demo/hardened

# Needs a throwaway cluster as the current kubectl context (see scripts/e2e.sh).
e2e:
	scripts/e2e.sh
