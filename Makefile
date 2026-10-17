.PHONY: install dev test dashboard mine clean docker

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	.venv/bin/pip install -e .
	@echo "✅ Installed. Activate with: source .venv/bin/activate"

dev:
	pip install -r requirements.txt
	pip install -e ".[dev]"

test:
	pytest tests/ -v
	python3 tests/test_miner.py
	python3 tests/test_stealth.py
	python3 tests/test_group.py

dashboard:
	hashflow dashboard --host 0.0.0.0 --port 8080

mine:
	@echo "Usage: make mine WALLET=4... USERNAME=alice"
	@if [ -z "$(WALLET)" ] || [ -z "$(USERNAME)" ]; then echo "Set WALLET and USERNAME"; exit 1; fi
	hashflow mine $(WALLET) --username $(USERNAME) --agree --dashboard

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__ hashflow/__pycache__ .venv
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docker:
	docker build -t hashflow:latest .
	docker-compose up

docker-build:
	docker build -t hashflow:latest .

fmt:
	@echo "No formatter configured yet"

help:
	@echo "Hashflow Makefile"
	@echo "  make install    - Setup venv and install"
	@echo "  make dev        - Install dev dependencies"
	@echo "  make test       - Run tests"
	@echo "  make dashboard  - Run dashboard"
	@echo "  make mine WALLET=... USERNAME=... - Start mining"
	@echo "  make docker     - Build and run docker"
	@echo "  make clean      - Clean artifacts"
