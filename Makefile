.PHONY: help lint lint-check test

help:
	@echo "Available targets:"
	@echo "  lint       - Run ruff to fix and format code"
	@echo "  lint-check - Check code without fixing"
	@echo "  test       - Run all tests"

lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 -m unittest discover -s tests -p "test_*.py" -v
