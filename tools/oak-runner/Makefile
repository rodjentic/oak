# ────────────────────────── Terminal colours ────────────────────────────
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)
BLUE   := $(shell tput -Txterm setaf 4)
RED    := $(shell tput -Txterm setaf 1)

# ────────────────────────── Project settings ────────────────────────────
PYTHON_VERSION := 3.11
VENV_NAME      := .venv
PROJECT_NAME   := oak-runner
REPO_ROOT      := $(shell pwd)
PYTHON         := $(REPO_ROOT)/$(VENV_NAME)/bin/python
PDM            := $(VENV_NAME)/bin/pdm

# ────────────────────────── Test settings ───────────────────────────────
TEST_PATH          := tests/
PYTEST_ARGS       ?= -v
COVERAGE_THRESHOLD := 80

# ────────────────────────── CLI default args ────────────────────────────
RUN_ARGS    ?= --help
ARAZZO_FILE ?= examples/petstore.arazzo.yaml
WORKFLOW_ID ?= get-pet-by-id
INPUTS      ?= '{"petId": "1"}'

.DEFAULT_GOAL := help

# =========================================================================
#  Help banner
# =========================================================================
help: ## Show this help message
	@echo ''
	@echo '${YELLOW}OAK Runner Development Guide${RESET}'
	@echo ''
	@echo '${YELLOW}Quick Start:${RESET}'
	@echo '  ${GREEN}make setup${RESET}         - Bootstrap env (uv) and install deps (pdm)'
	@echo '  ${GREEN}make run${RESET}           - Test the CLI'
	@echo '  ${GREEN}make test${RESET}          - Run tests'
	@echo '  ${GREEN}make format${RESET}        - Format code'
	@echo '  ${GREEN}make lint${RESET}          - Lint code'
	@echo '  ${GREEN}make clean${RESET}         - Clean virtualenv and cache'
	@echo ''
	@echo '${YELLOW}Development Workflow:${RESET}'
	@echo '  1. ${GREEN}make setup${RESET}         - One-time setup (uv + pdm)'
	@echo '  2. ${GREEN}make run${RESET}           - Test the CLI'
	@echo '  3. ${GREEN}make test${RESET}          - Run tests before committing'
	@echo ''
	@echo '${YELLOW}Available Targets:${RESET}'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'
	@echo ''

# =========================================================================
#  Setup - Bootstrap environment with uv + PDM
# =========================================================================
.PHONY: check-uv
check-uv: ## Check if uv is installed, install if missing
	@if ! command -v uv &>/dev/null; then \
		echo "${RED}uv is not installed. Installing uv...${RESET}"; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
		export PATH="$$HOME/.cargo/bin:$$PATH"; \
		if ! command -v uv &>/dev/null; then \
			echo "${RED}Failed to install uv. Please install manually: https://docs.astral.sh/uv/getting-started/installation/${RESET}"; \
			exit 1; \
		fi; \
		echo "${GREEN}✓ uv installed successfully${RESET}"; \
	else \
		echo "${GREEN}✓ uv is already installed${RESET}"; \
	fi

.PHONY: env
env: check-uv ## Create local virtualenv with uv + Python and install PDM
	@echo "${BLUE}Creating virtualenv with Python $(PYTHON_VERSION)...${RESET}"
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	if [ ! -d "$(VENV_NAME)" ]; then \
		uv venv --python $(PYTHON_VERSION) $(VENV_NAME); \
	else \
		echo "${YELLOW}Virtual environment already exists${RESET}"; \
	fi
	@echo "${BLUE}Installing PDM into .venv...${RESET}"
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	. $(VENV_NAME)/bin/activate && \
	python -m ensurepip --upgrade && \
	python -m pip install --upgrade pip && \
	python -m pip install pdm
	@echo "${GREEN}✓ Virtualenv ready with PDM installed${RESET}"

.PHONY: setup
setup: env ## Setup environment and install dependencies
	@echo "${BLUE}Installing dependencies with PDM...${RESET}"
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	. $(VENV_NAME)/bin/activate && pdm install --dev
	@echo "${GREEN}✓ All dependencies installed. You can now run 'make run'${RESET}"

# =========================================================================
#  Development commands - All use PDM
# =========================================================================
.PHONY: run
run: ## Run OAK Runner CLI with default arguments
	@$(PDM) run python -m oak_runner $(RUN_ARGS)

.PHONY: test
test: ## Run tests with coverage
	@$(PDM) run pytest $(TEST_PATH) $(PYTEST_ARGS) \
		--cov=src/oak_runner \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-fail-under=$(COVERAGE_THRESHOLD)

.PHONY: test-fast
test-fast: ## Run tests without coverage (faster)
	@$(PDM) run pytest $(TEST_PATH) $(PYTEST_ARGS) -x

.PHONY: test-unit
test-unit: ## Run only unit tests
	@$(PDM) run pytest tests/unit $(PYTEST_ARGS) \
		--cov=src/oak_runner --cov-report=term-missing

.PHONY: test-integration
test-integration: ## Run only integration tests
	@$(PDM) run pytest tests/integration $(PYTEST_ARGS) \
		--cov=src/oak_runner --cov-report=term-missing

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@$(PDM) run pytest tests/e2e $(PYTEST_ARGS)

.PHONY: format
format: ## Format code with Ruff and isort
	@echo "${BLUE}Formatting code...${RESET}"
	@$(PDM) run ruff check src/ tests/ examples/ --fix
	@$(PDM) run ruff format .
	@$(PDM) run isort .
	@echo "${GREEN}✓ Code formatted successfully${RESET}"

.PHONY: lint
lint: ## Run linters
	@echo "${BLUE}Running linters...${RESET}"
	@$(PDM) run ruff check src/ tests/ examples/
	@$(PDM) run ruff format --check src/ tests/ examples/
	@$(PDM) run mypy src/ tests/ examples/ --ignore-missing-imports

.PHONY: type-check
type-check: ## Run type checking with mypy
	@$(PDM) run mypy src/ --ignore-missing-imports

# =========================================================================
#  CLI and demo commands
# =========================================================================
.PHONY: demo
demo: ## Run a demo workflow (requires example files)
	@echo "${BLUE}Running demo workflow...${RESET}"
	@if [ -f "$(ARAZZO_FILE)" ]; then \
		$(PDM) run python -m oak_runner execute-workflow $(ARAZZO_FILE) \
			--workflow-id $(WORKFLOW_ID) --inputs $(INPUTS); \
	else \
		echo "${YELLOW}Demo file $(ARAZZO_FILE) not found. Showing help...${RESET}"; \
		$(PDM) run python -m oak_runner --help; \
	fi

.PHONY: list-workflows
list-workflows: ## List workflows in an Arazzo file
	@echo "${BLUE}Listing workflows...${RESET}"
	@if [ -f "$(ARAZZO_FILE)" ]; then \
		$(PDM) run python -m oak_runner list-workflows $(ARAZZO_FILE); \
	else \
		echo "${RED}Arazzo file $(ARAZZO_FILE) not found${RESET}"; \
		echo "${YELLOW}Set ARAZZO_FILE=path/to/your/file.arazzo.yaml${RESET}"; \
	fi

.PHONY: show-env
show-env: ## Show environment variable mappings
	@echo "${BLUE}Showing environment variable mappings...${RESET}"
	@if [ -f "$(ARAZZO_FILE)" ]; then \
		$(PDM) run python -m oak_runner show-env-mappings $(ARAZZO_FILE); \
	else \
		echo "${RED}Arazzo file $(ARAZZO_FILE) not found${RESET}"; \
		echo "${YELLOW}Set ARAZZO_FILE=path/to/your/file.arazzo.yaml${RESET}"; \
	fi

# =========================================================================
#  Build and utility commands
# =========================================================================
.PHONY: build
build: clean format lint test ## Build package for distribution
	@echo "${BLUE}Building package for distribution...${RESET}"
	@$(PDM) build
	@echo "${GREEN}✓ Package built successfully${RESET}"

.PHONY: clean
clean: ## Remove virtualenv and cached files
	@echo "${BLUE}Cleaning project...${RESET}"
	rm -rf $(VENV_NAME) **/__pycache__ .pytest_cache .pdm-cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.py[co]" -delete
	rm -rf build/ dist/ *.egg-info
	@echo "${GREEN}✓ Cleaned${RESET}"

.PHONY: pre-commit
pre-commit: format lint test ## Run all checks before committing
	@echo "${GREEN}✓ All pre-commit checks passed${RESET}"

.PHONY: structure
structure: ## Show project structure
	@echo "${YELLOW}OAK Runner Project Structure:${RESET}"
	@echo "${BLUE}"
	@if command -v tree &>/dev/null; then \
		tree -a -I '.git|.venv|__pycache__|*.py[co]|.pytest_cache|.ruff_cache|.coverage|htmlcov|dist|build|*.egg-info|.pdm-cache'; \
	else \
		find . -not -path '*/\.*' -not -path '*.py[co]' -not -path '*/__pycache__/*' \
			-not -path './.venv/*' -not -path './build/*' -not -path './dist/*' \
			-not -path './*.egg-info/*' -not -path './.pdm-cache/*' | sort | \
			sed -e "s/[^-][^\/]*\// │   /g" -e "s/├── /│── /" -e "s/└── /└── /"; \
	fi
	@echo "${RESET}"

.PHONY: add-paths
add-paths: ## Add file paths as first-line comments to all Python files
	@echo "${BLUE}Adding file paths as comments to Python files...${RESET}"
	@$(PDM) run python - <<'PY'
	import os, sys, traceback
	def update_file(filepath):
	    try:
	        relpath = os.path.relpath(filepath)
	        print(f"Processing {relpath}...")
	        with open(filepath, "r", encoding="utf-8") as f:
	            lines = f.read().splitlines()
	        if not lines:
	            print(f"  Skipping {relpath}: empty file"); return
	        if lines[0].lstrip().startswith("#"): 
	            lines[0] = f"# {relpath}"
	        else: 
	            lines.insert(0, f"# {relpath}")
	        with open(filepath, "w", encoding="utf-8") as f:
	            f.write("\n".join(lines) + "\n")
	        print(f"  Updated {relpath}")
	    except Exception as e:
	        print(f"  Error: {e}")
	def main():
	    cnt = 0
	    for root, _, files in os.walk("."):
	        if any(x in root for x in [".git",".venv","__pycache__",".mypy_cache",
	                                   ".pytest_cache",".ruff_cache","build","dist",".egg-info",".pdm-cache"]):
	            continue
	        for file in files:
	            if file.endswith(".py"):
	                update_file(os.path.join(root, file)); cnt += 1
	    print(f"Processed {cnt} Python files")
	if __name__ == "__main__": main()
	PY
	@echo "${GREEN}✓ File paths added to all Python files${RESET}"

.PHONY: info
info: ## Show environment information
	@echo "${YELLOW}OAK Runner Development Environment Info:${RESET}"
	@echo "${BLUE}Python version:${RESET} $(shell $(PYTHON) --version 2>/dev/null || echo 'Not installed')"
	@echo "${BLUE}Virtual environment:${RESET} $(VENV_NAME)"
	@echo "${BLUE}Project root:${RESET} $(REPO_ROOT)"
	@echo "${BLUE}Package manager:${RESET} PDM (via uv-created venv)"
	@echo "${BLUE}uv installed:${RESET} $(shell command -v uv &>/dev/null && echo 'Yes' || echo 'No')"
	@echo "${BLUE}OAK Runner installed:${RESET} $(shell $(PYTHON) -c 'import importlib.util; print("Yes" if importlib.util.find_spec("oak_runner") else "No")' 2>/dev/null || echo 'No')"

# Git utility targets  
.PHONY: prune-branches
prune-branches: ## Remove local branches that are no longer tracked on the remote
	@echo "${BLUE}Pruning local branches that are no longer tracked on the remote...${RESET}"
	@git fetch -p && \
	  for branch in $$(git branch -vv | awk '/: gone]/{print $$1}'); do \
	    git branch -D $$branch; \
	  done
	@echo "${GREEN}✓ Stale branches removed${RESET}"