# Terminal colors
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)
BLUE   := $(shell tput -Txterm setaf 4)
RED    := $(shell tput -Txterm setaf 1)

# Project settings
PYTHON_VERSION := 3.11
VENV_NAME := .venv
PROJECT_NAME := oak-runner
REPO_ROOT := $(shell pwd)
PYTHON := $(REPO_ROOT)/$(VENV_NAME)/bin/python
PIP := $(REPO_ROOT)/$(VENV_NAME)/bin/pip

# Test settings
TEST_PATH := tests/
PYTEST_ARGS ?= -v
COVERAGE_THRESHOLD := 80

# CLI run arguments
RUN_ARGS ?= --help
ARAZZO_FILE ?= examples/petstore.arazzo.yaml
WORKFLOW_ID ?= get-pet-by-id
INPUTS ?= '{"petId": "1"}'

help: ## Show this help message
	@echo ''
	@echo '${YELLOW}OAK Runner Development Guide${RESET}'
	@echo ''
	@echo '${YELLOW}Quick Start (recommended):${RESET}'
	@echo '  Setup:      ${GREEN}make setup${RESET}           - Full development environment with uv'
	@echo '  Simple:     ${GREEN}make setup-simple${RESET}    - Fallback setup using standard Python'
	@echo '  Activate:   ${GREEN}source setup.sh${RESET}      - Activate environment (or setup-simple.sh)'
	@echo '  Install:    ${GREEN}make install${RESET}         - Install OAK Runner'
	@echo '  Test:       ${GREEN}make test${RESET}            - Run tests'
	@echo ''
	@echo '${YELLOW}Development Workflow:${RESET}'
	@echo '  1. ${GREEN}make setup${RESET}         - Create environment and install everything'
	@echo '  2. ${GREEN}source setup.sh${RESET}    - Activate the environment'
	@echo '  3. ${GREEN}make run${RESET}           - Test the CLI'
	@echo '  4. ${GREEN}make test${RESET}          - Run tests before committing'
	@echo ''
	@echo '${YELLOW}If uv is not available:${RESET}'
	@echo '  1. ${GREEN}make setup-simple${RESET}  - Use standard Python instead'
	@echo '  2. ${GREEN}source setup-simple.sh${RESET} - Activate the environment'
	@echo ''
	@echo '${YELLOW}Available Targets:${RESET}'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ''

# Development environment targets
.PHONY: check-uv
check-uv: ## Check if uv is installed and install if missing
	@if ! command -v uv &> /dev/null; then \
		echo "${YELLOW}uv is not installed. Installing uv...${RESET}"; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
		export PATH="$HOME/.cargo/bin:$PATH"; \
		if ! command -v uv &> /dev/null; then \
			echo "${RED}Failed to install uv automatically.${RESET}"; \
			echo "${YELLOW}Please install uv manually:${RESET}"; \
			echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"; \
			echo "  or visit: https://docs.astral.sh/uv/getting-started/installation/"; \
			exit 1; \
		fi; \
		echo "${GREEN}uv installed successfully${RESET}"; \
	else \
		echo "${GREEN}uv is already installed${RESET}"; \
	fi

.PHONY: env
env: check-uv ## Create virtual environment using uv
	@echo "${BLUE}Creating virtual environment with Python $(PYTHON_VERSION)...${RESET}"
	uv venv --python $(PYTHON_VERSION) $(VENV_NAME)
	@echo "${GREEN}Virtual environment created. Activate it with:${RESET}"
	@echo "source $(VENV_NAME)/bin/activate"

.PHONY: env-pip
env-pip: ## Create virtual environment using standard Python (fallback)
	@echo "${BLUE}Creating virtual environment with standard Python...${RESET}"
	python$(PYTHON_VERSION) -m venv $(VENV_NAME) || python3 -m venv $(VENV_NAME) || python -m venv $(VENV_NAME)
	@echo "${GREEN}Virtual environment created. Activate it with:${RESET}"
	@echo "source $(VENV_NAME)/bin/activate"

.PHONY: install
install: ## Install OAK Runner package in development mode
	@echo "${BLUE}Installing OAK Runner package...${RESET}"
	@if command -v uv &> /dev/null; then \
		uv pip install -e .; \
	else \
		$(PIP) install -e .; \
	fi
	@echo "${GREEN}OAK Runner installed successfully${RESET}"
	@# Verify installation
	@$(PYTHON) -c "import oak_runner; print(f'OAK Runner installed at: {oak_runner.__file__}')" || echo "${RED}Installation verification failed${RESET}"

.PHONY: install-dev
install-dev: ## Install development dependencies
	@echo "${BLUE}Installing development tools...${RESET}"
	@if command -v uv &> /dev/null; then \
		uv pip install -e ".[dev]"; \
	else \
		$(PIP) install -e ".[dev]"; \
	fi
	@echo "${GREEN}Development dependencies installed successfully${RESET}"

.PHONY: install-all
install-all: install-dev ## Install OAK Runner with all optional dependencies
	@echo "${BLUE}Installing OAK Runner with all optional dependencies...${RESET}"
	@if command -v uv &> /dev/null; then \
		uv pip install -e ".[all]"; \
	else \
		$(PIP) install -e ".[all]"; \
	fi
	@echo "${GREEN}All dependencies installed successfully${RESET}"

.PHONY: setup
setup: ## Create environment and install full development dependencies
	@echo "${BLUE}Creating complete development environment...${RESET}"
	@echo '#!/bin/bash' > setup.sh
	@echo 'echo "${BLUE}Setting up OAK Runner development environment...${RESET}"' >> setup.sh
	@echo '' >> setup.sh
	@echo '# Check if uv is installed' >> setup.sh
	@echo 'if ! command -v uv &> /dev/null; then' >> setup.sh
	@echo '    echo "${RED}uv is not installed. Installing uv...${RESET}"' >> setup.sh
	@echo '    curl -LsSf https://astral.sh/uv/install.sh | sh' >> setup.sh
	@echo '    export PATH="$HOME/.cargo/bin:$PATH"' >> setup.sh
	@echo '    if ! command -v uv &> /dev/null; then' >> setup.sh
	@echo '        echo "${RED}Failed to install uv. Please install manually: https://docs.astral.sh/uv/getting-started/installation/${RESET}"' >> setup.sh
	@echo '        exit 1' >> setup.sh
	@echo '    fi' >> setup.sh
	@echo 'fi' >> setup.sh
	@echo '' >> setup.sh
	@echo 'echo "${BLUE}Creating virtual environment...${RESET}"' >> setup.sh
	@echo 'uv venv --python $(PYTHON_VERSION) $(VENV_NAME)' >> setup.sh
	@echo 'source $(VENV_NAME)/bin/activate' >> setup.sh
	@echo 'echo "${BLUE}Installing OAK Runner with development dependencies...${RESET}"' >> setup.sh
	@echo 'make install-all' >> setup.sh
	@echo 'echo "${GREEN}Setup complete! Development environment ready.${RESET}"' >> setup.sh
	@echo 'echo "${YELLOW}Environment activated. You can now run:${RESET}"' >> setup.sh
	@echo 'echo "  make run          - Test the CLI"' >> setup.sh
	@echo 'echo "  make test         - Run tests"' >> setup.sh
	@echo 'echo "  make demo         - Run demo workflow"' >> setup.sh
	@echo '' >> setup.sh
	@echo '# Self-destruct (works whether executed or sourced)' >> setup.sh
	@echo 'if [ -n "$${BASH_SOURCE[0]}" ]; then' >> setup.sh
	@echo '    _self="$${BASH_SOURCE[0]}"' >> setup.sh
	@echo 'elif [ -n "$${(%):-%N}" ]; then' >> setup.sh
	@echo '    _self="$${(%):-%N}"' >> setup.sh
	@echo 'else' >> setup.sh
	@echo '    _self="$$0"' >> setup.sh
	@echo 'fi' >> setup.sh
	@echo '[ -f "$$_self" ] && rm -- "$$_self"' >> setup.sh
	@echo 'unset _self' >> setup.sh
	@chmod +x setup.sh
	@echo "${GREEN}Environment setup script created. To complete setup, run:${RESET}"
	@echo "${YELLOW}source setup.sh${RESET}"

.PHONY: setup-simple
setup-simple: ## Simple setup using standard Python (no uv required)
	@echo "${BLUE}Creating simple development environment...${RESET}"
	@echo '#!/bin/bash' > setup-simple.sh
	@echo 'echo "${BLUE}Setting up OAK Runner development environment (simple mode)...${RESET}"' >> setup-simple.sh
	@echo 'echo "${BLUE}Creating virtual environment...${RESET}"' >> setup-simple.sh
	@echo 'python3 -m venv $(VENV_NAME) || python -m venv $(VENV_NAME)' >> setup-simple.sh
	@echo 'source $(VENV_NAME)/bin/activate' >> setup-simple.sh
	@echo 'echo "${BLUE}Upgrading pip...${RESET}"' >> setup-simple.sh
	@echo 'pip install --upgrade pip' >> setup-simple.sh
	@echo 'echo "${BLUE}Installing OAK Runner with development dependencies...${RESET}"' >> setup-simple.sh
	@echo 'pip install -e ".[dev]" || pip install -e .' >> setup-simple.sh
	@echo 'echo "${GREEN}Setup complete! Development environment ready.${RESET}"' >> setup-simple.sh
	@echo 'echo "${YELLOW}Environment activated. You can now run:${RESET}"' >> setup-simple.sh
	@echo 'echo "  make run          - Test the CLI"' >> setup-simple.sh
	@echo 'echo "  make test         - Run tests"' >> setup-simple.sh
	@echo 'echo "  make demo         - Run demo workflow"' >> setup-simple.sh
	@echo '' >> setup-simple.sh
	@echo '# Self-destruct (works whether executed or sourced)' >> setup-simple.sh
	@echo 'if [ -n "$${BASH_SOURCE[0]}" ]; then' >> setup-simple.sh
	@echo '    _self="$${BASH_SOURCE[0]}"' >> setup-simple.sh
	@echo 'elif [ -n "$${(%):-%N}" ]; then' >> setup-simple.sh
	@echo '    _self="$${(%):-%N}"' >> setup-simple.sh
	@echo 'else' >> setup-simple.sh
	@echo '    _self="$$0"' >> setup-simple.sh
	@echo 'fi' >> setup-simple.sh
	@echo '[ -f "$$_self" ] && rm -- "$$_self"' >> setup-simple.sh
	@echo 'unset _self' >> setup-simple.sh
	@chmod +x setup-simple.sh
	@echo "${GREEN}Simple environment setup script created. To complete setup, run:${RESET}"
	@echo "${YELLOW}source setup-simple.sh${RESET}"

# Testing targets
.PHONY: test
test: ## Run tests with coverage
	@echo "${BLUE}Running tests with coverage...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest $(TEST_PATH) $(PYTEST_ARGS) \
		--cov=src/oak_runner \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-fail-under=$(COVERAGE_THRESHOLD)

.PHONY: test-fast
test-fast: ## Run tests without coverage (faster)
	@echo "${BLUE}Running fast tests...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest $(TEST_PATH) $(PYTEST_ARGS) -x

.PHONY: test-unit
test-unit: ## Run only unit tests
	@echo "${BLUE}Running unit tests...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest tests/unit $(PYTEST_ARGS) --cov=src/oak_runner --cov-report=term-missing

.PHONY: test-integration
test-integration: ## Run only integration tests
	@echo "${BLUE}Running integration tests...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest tests/integration $(PYTEST_ARGS) --cov=src/oak_runner --cov-report=term-missing

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "${BLUE}Running end-to-end tests...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest tests/e2e $(PYTEST_ARGS)

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	@echo "${BLUE}Running tests in watch mode...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest-watch -- $(TEST_PATH) $(PYTEST_ARGS)

# Code quality targets
.PHONY: format
format: ## Format code with Ruff and isort
	@echo "${BLUE}Formatting code...${RESET}"
	$(PYTHON) -m ruff check src/ tests/ examples/ --fix
	$(PYTHON) -m ruff format .
	$(PYTHON) -m isort .
	@echo "${GREEN}Code formatted successfully${RESET}"

.PHONY: lint
lint: ## Run linters
	@echo "${BLUE}Running linters...${RESET}"
	$(PYTHON) -m ruff check src/ tests/ examples/
	$(PYTHON) -m ruff format --check src/ tests/ examples/
	$(PYTHON) -m mypy src/ tests/ examples/ --ignore-missing-imports

.PHONY: type-check
type-check: ## Run type checking with mypy
	@echo "${BLUE}Running type checking...${RESET}"
	$(PYTHON) -m mypy src/ --ignore-missing-imports

.PHONY: security
security: ## Run security checks
	@echo "${BLUE}Running security checks...${RESET}"
	$(PYTHON) -m bandit -r src/ -f json || true
	$(PYTHON) -m safety check || true

# CLI and demo targets
.PHONY: run
run: ## Run OAK Runner CLI with default arguments
	@echo "${BLUE}Running OAK Runner CLI...${RESET}"
	$(PYTHON) -m oak_runner $(RUN_ARGS)

.PHONY: demo
demo: ## Run a demo workflow (requires example files)
	@echo "${BLUE}Running demo workflow...${RESET}"
	@if [ -f "$(ARAZZO_FILE)" ]; then \
		$(PYTHON) -m oak_runner execute-workflow $(ARAZZO_FILE) --workflow-id $(WORKFLOW_ID) --inputs $(INPUTS); \
	else \
		echo "${YELLOW}Demo file $(ARAZZO_FILE) not found. Creating a simple demo...${RESET}"; \
		$(PYTHON) -m oak_runner --help; \
	fi

.PHONY: list-workflows
list-workflows: ## List workflows in an Arazzo file
	@echo "${BLUE}Listing workflows...${RESET}"
	@if [ -f "$(ARAZZO_FILE)" ]; then \
		$(PYTHON) -m oak_runner list-workflows $(ARAZZO_FILE); \
	else \
		echo "${RED}Arazzo file $(ARAZZO_FILE) not found${RESET}"; \
		echo "${YELLOW}Set ARAZZO_FILE=path/to/your/file.arazzo.yaml${RESET}"; \
	fi

.PHONY: show-env
show-env: ## Show environment variable mappings
	@echo "${BLUE}Showing environment variable mappings...${RESET}"
	@if [ -f "$(ARAZZO_FILE)" ]; then \
		$(PYTHON) -m oak_runner show-env-mappings $(ARAZZO_FILE); \
	else \
		echo "${RED}Arazzo file $(ARAZZO_FILE) not found${RESET}"; \
		echo "${YELLOW}Set ARAZZO_FILE=path/to/your/file.arazzo.yaml${RESET}"; \
	fi

# Build and distribution targets
.PHONY: clean
clean: ## Clean build artifacts and cache
	@echo "${BLUE}Cleaning build artifacts and cache...${RESET}"
	rm -rf build/ dist/ *.egg-info .coverage .mypy_cache .pytest_cache .ruff_cache $(VENV_NAME)
	rm -rf htmlcov/ .coverage.*
	rm -rf setup.sh
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	@echo "${GREEN}Cleaned all build artifacts and cache.${RESET}"

.PHONY: build
build: clean format lint test ## Build package for distribution
	@echo "${BLUE}Building package for distribution...${RESET}"
	$(PYTHON) -m build
	@echo "${GREEN}Package built successfully. Distribution files in dist/ directory.${RESET}"

.PHONY: build-fast
build-fast: clean ## Build package without running tests (faster)
	@echo "${BLUE}Building package (fast mode)...${RESET}"
	$(PYTHON) -m build
	@echo "${GREEN}Package built successfully.${RESET}"

.PHONY: install-from-build
install-from-build: build ## Install from built wheel
	@echo "${BLUE}Installing from built wheel...${RESET}"
	$(PIP) install dist/*.whl --force-reinstall
	@echo "${GREEN}Installed from wheel successfully${RESET}"

.PHONY: publish-test
publish-test: build ## Publish package to TestPyPI
	@echo "${BLUE}Publishing package to TestPyPI...${RESET}"
	$(PYTHON) -m twine upload --repository testpypi dist/*
	@echo "${GREEN}Package published to TestPyPI successfully!${RESET}"

.PHONY: publish
publish: build ## Publish package to PyPI
	@echo "${BLUE}Publishing package to PyPI...${RESET}"
	@echo "${YELLOW}This will publish OAK Runner to PyPI.${RESET}"
	@echo "${YELLOW}Are you sure you want to continue? (y/n)${RESET}"
	@read -p " " yn; \
	if [ "$$yn" = "y" ]; then \
		$(PYTHON) -m twine upload dist/*; \
		echo "${GREEN}Package published successfully!${RESET}"; \
	else \
		echo "${YELLOW}Publishing cancelled.${RESET}"; \
	fi

# Development workflow targets
.PHONY: pre-commit
pre-commit: format lint test ## Run all checks before committing
	@echo "${GREEN}✓ All pre-commit checks passed${RESET}"

.PHONY: ci
ci: lint type-check security test ## Run full CI pipeline
	@echo "${GREEN}✓ All CI checks passed${RESET}"

.PHONY: dev-install
dev-install: ## Quick development installation (no tests)
	@echo "${BLUE}Quick development installation...${RESET}"
	uv pip install -e ".[dev]"
	@echo "${GREEN}Development installation complete${RESET}"

# Documentation targets
.PHONY: docs
docs: ## Generate documentation
	@echo "${BLUE}Generating documentation...${RESET}"
	@if [ -d "docs/" ]; then \
		cd docs && $(PYTHON) -m sphinx -b html . _build/html; \
		echo "${GREEN}Documentation generated in docs/_build/html/${RESET}"; \
	else \
		echo "${YELLOW}No docs directory found. Skipping documentation generation.${RESET}"; \
	fi

.PHONY: docs-serve
docs-serve: docs ## Serve documentation locally
	@echo "${BLUE}Serving documentation locally...${RESET}"
	@if [ -d "docs/_build/html" ]; then \
		cd docs/_build/html && $(PYTHON) -m http.server 8000; \
	else \
		echo "${RED}Documentation not built. Run 'make docs' first.${RESET}"; \
	fi

# Utility targets
.PHONY: structure
structure: ## Show project structure
	@echo "${YELLOW}OAK Runner Project Structure:${RESET}"
	@echo "${BLUE}"
	@if command -v tree > /dev/null; then \
		tree -a -I '.git|.venv|__pycache__|*.pyc|*.pyo|*.pyd|.pytest_cache|.ruff_cache|.coverage|htmlcov|dist|build|*.egg-info'; \
	else \
		find . -not -path '*/\.*' -not -path '*.pyc' -not -path '*/__pycache__/*' \
			-not -path './.venv/*' -not -path './build/*' -not -path './dist/*' \
			-not -path './*.egg-info/*' \
			| sort | \
			sed -e "s/[^-][^\/]*\// │   /g" -e "s/├── /│── /" -e "s/└── /└── /"; \
	fi
	@echo "${RESET}"

.PHONY: add-paths
add-paths: ## Add file paths as first-line comments to all Python files
	@echo "${BLUE}Adding file paths as comments to Python files...${RESET}"
	@echo '#!/usr/bin/env python' > add_paths.py
	@echo '# add_paths.py' >> add_paths.py
	@echo 'import os' >> add_paths.py
	@echo 'import sys' >> add_paths.py
	@echo 'import traceback' >> add_paths.py
	@echo '' >> add_paths.py
	@echo 'def update_file(filepath):' >> add_paths.py
	@echo '    try:' >> add_paths.py
	@echo '        relpath = os.path.relpath(filepath)' >> add_paths.py
	@echo '        print(f"Processing {relpath}...")' >> add_paths.py
	@echo '        with open(filepath, "r") as f:' >> add_paths.py
	@echo '            content = f.read()' >> add_paths.py
	@echo '        lines = content.split("\\n")' >> add_paths.py
	@echo '        if not lines:' >> add_paths.py
	@echo '            print(f"  Skipping {relpath}: empty file")' >> add_paths.py
	@echo '            return' >> add_paths.py
	@echo '        has_path_comment = False' >> add_paths.py
	@echo '        if lines[0].strip().startswith("#"):' >> add_paths.py
	@echo '            has_path_comment = True' >> add_paths.py
	@echo '            old_line = lines[0]' >> add_paths.py
	@echo '            lines[0] = f"# {relpath}"' >> add_paths.py
	@echo '            print(f"  Replacing comment: {old_line} -> # {relpath}")' >> add_paths.py
	@echo '        else:' >> add_paths.py
	@echo '            lines.insert(0, f"# {relpath}")' >> add_paths.py
	@echo '            print(f"  Adding new comment: # {relpath}")' >> add_paths.py
	@echo '        with open(filepath, "w") as f:' >> add_paths.py
	@echo '            f.write("\\n".join(lines))' >> add_paths.py
	@echo '        print(f"  Updated {relpath}")' >> add_paths.py
	@echo '    except Exception as e:' >> add_paths.py
	@echo '        print(f"  Error processing {filepath}: {str(e)}")' >> add_paths.py
	@echo '        traceback.print_exc()' >> add_paths.py
	@echo '' >> add_paths.py
	@echo 'def main():' >> add_paths.py
	@echo '    try:' >> add_paths.py
	@echo '        count = 0' >> add_paths.py
	@echo '        print("Starting file scan...")' >> add_paths.py
	@echo '        for root, dirs, files in os.walk("."):' >> add_paths.py
	@echo '            if any(x in root for x in [".git", ".venv", "__pycache__", ".mypy_cache",' >> add_paths.py
	@echo '                                      ".pytest_cache", ".ruff_cache", "build", "dist", ".egg-info"]):' >> add_paths.py
	@echo '                continue' >> add_paths.py
	@echo '            for file in files:' >> add_paths.py
	@echo '                if file.endswith(".py"):' >> add_paths.py
	@echo '                    filepath = os.path.join(root, file)' >> add_paths.py
	@echo '                    update_file(filepath)' >> add_paths.py
	@echo '                    count += 1' >> add_paths.py
	@echo '        print(f"Processed {count} Python files")' >> add_paths.py
	@echo '    except Exception as e:' >> add_paths.py
	@echo '        print(f"Fatal error: {str(e)}")' >> add_paths.py
	@echo '        traceback.print_exc()' >> add_paths.py
	@echo '        sys.exit(1)' >> add_paths.py
	@echo '' >> add_paths.py
	@echo 'if __name__ == "__main__":' >> add_paths.py
	@echo '    main()' >> add_paths.py
	@chmod +x add_paths.py
	@$(PYTHON) add_paths.py
	@rm add_paths.py
	@echo "${GREEN}✓ File paths added to all Python files${RESET}"

.PHONY: check-deps
check-deps: ## Check for outdated dependencies
	@echo "${BLUE}Checking for outdated dependencies...${RESET}"
	$(PIP) list --outdated

.PHONY: deps-tree
deps-tree: ## Show dependency tree
	@echo "${BLUE}Showing dependency tree...${RESET}"
	$(PIP) show oak-runner || echo "${YELLOW}OAK Runner not installed${RESET}"
	@if command -v pipdeptree > /dev/null; then \
		pipdeptree; \
	else \
		echo "${YELLOW}Install pipdeptree for dependency tree: pip install pipdeptree${RESET}"; \
	fi

.PHONY: profile
profile: ## Profile test execution
	@echo "${BLUE}Profiling test execution...${RESET}"
	PYTHONPATH="$(REPO_ROOT)/src:$(PYTHONPATH)" \
	$(PYTHON) -m pytest $(TEST_PATH) --profile-svg

# Git utility targets
.PHONY: prune-branches
prune-branches: ## Remove local branches that are no longer tracked on the remote
	@echo "${BLUE}Pruning local branches that are no longer tracked on the remote...${RESET}"
	@git fetch -p && \
	  for branch in $$(git branch -vv | grep ': gone]' | awk '{print $$1}'); do \
	    git branch -D $$branch; \
	  done
	@echo "${GREEN}Stale branches have been removed.${RESET}"

# Environment info
.PHONY: info
info: ## Show environment information
	@echo "${YELLOW}OAK Runner Development Environment Info:${RESET}"
	@echo "${BLUE}Python version:${RESET} $(shell $(PYTHON) --version 2>/dev/null || echo 'Not installed')"
	@echo "${BLUE}Virtual environment:${RESET} $(VENV_NAME)"
	@echo "${BLUE}Project root:${RESET} $(REPO_ROOT)"
	@echo "${BLUE}Package manager:${RESET} uv"
	@echo "${BLUE}OAK Runner installed:${RESET} $(shell $(PYTHON) -c 'import oak_runner; print("Yes")' 2>/dev/null || echo 'No')"
	@echo "${BLUE}Available commands:${RESET}"
	@echo "  make run           - Test CLI"
	@echo "  make demo          - Run demo workflow"
	@echo "  make test          - Run tests"
	@echo "  make format        - Format code"
	@echo "  make build         - Build package"

.DEFAULT_GOAL := help