.PHONY: init black lint security build clean test-unit test-experiments test $(wildcard test-*)

# Environment variables
MAMBA_EXE ?= micromamba
ENV_NAME := adcyder-attack-simulator
MAMBA_DEV := $(MAMBA_EXE) -n $(ENV_NAME)-dev run
MAMBA := $(MAMBA_EXE) -n $(ENV_NAME) run
PYTHON := python3
SRC_DIR := src
REPORTS_DIR := test-results

# Export PYTHONPATH
PYTHONPATH := $(SRC_DIR):$(PYTHONPATH)
export PYTHONPATH

# Metasploit paths
MSFRPCD_PATH := $(shell which msfrpcd)
MSF_PATH := $(shell which msfconsole)
MSFVENOM_PATH := $(shell which msfvenom)

# Common test environment settings
TEST_ENV := MSF_PATH="$(MSF_PATH)" \
    MSFVENOM_PATH="$(MSFVENOM_PATH)" \
    MSFRPCD_PATH="$(MSFRPCD_PATH)" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Colors for pretty printing
COLOR_RESET := \033[0m
COLOR_BOLD := \033[1m
COLOR_GREEN := \033[32m
COLOR_RED := \033[31m

# Create necessary directories
$(shell mkdir -p $(REPORTS_DIR))

# Targets
init: environment-dev.yml
	@echo "Creating development environment..."
	@$(MAMBA_EXE) create -yf environment-dev.yml
	@${MAMBA_EXE} install -n adcyder-attack-simulator-dev -yf environment.yml
	@echo "$(COLOR_GREEN)Development environment created successfully$(COLOR_RESET)"

black:
	@echo "Formatting code..."
	@${MAMBA_DEV} black -q $(SRC_DIR)/
	@echo "$(COLOR_GREEN)Code formatting complete$(COLOR_RESET)"

lint:
	@echo "Checking code format..."
	@${MAMBA_DEV} black --check --diff -q $(SRC_DIR)/

type-check:
	@echo "Running type checks..."
	@${MAMBA_DEV} mypy --install-types --warn-unreachable --strict --non-interactive $(SRC_DIR)/ tests/
	@echo "$(COLOR_GREEN)Type checking complete$(COLOR_RESET)"

security:
	@echo "Running security checks..."
	@# We don't care about B108 (/tmp usage)
	@${MAMBA_DEV} bandit -q -ll -ii -r --skip B108 --exclude venv $(SRC_DIR)/
	@echo "Checking dependencies for security issues..."

	@# PYSEC-2022-42969 is an old vuln in the py library used by bandit with no fix available
	@${MAMBA_DEV} pip-audit	--ignore-vuln PYSEC-2022-42969
	@${MAMBA_DEV} pip-audit	--requirement src/historian/requirements.txt
	@${MAMBA_DEV} pip-audit	--requirement src/injector/requirements.txt

	@echo "$(COLOR_GREEN)Security checks complete$(COLOR_RESET)"

build: lint test-all environment.yml
	@echo "Creating production environment..."
	@$(MAMBA_EXE) create -yf environment.yml
	@echo "$(COLOR_GREEN)Production environment created successfully$(COLOR_RESET)"

security-postcheck:
	@echo "Checking dependencies for security issues..."
	@# PYSEC-2022-42969 is an old vuln in the py library used by bandit with no fix available
	@${MAMBA_DEV} pip-audit	--ignore-vuln PYSEC-2022-42969
	@${MAMBA_DEV} pip-audit	--requirement src/historian/requirements.txt
	@${MAMBA_DEV} pip-audit	--requirement src/injector/requirements.txt
	@echo "$(COLOR_GREEN)Security postcheck complete$(COLOR_RESET)"

protobuf:
	@echo "Compiling Protocol Buffers..."
	@$(MAMBA_DEV) python -m grpc_tools.protoc --proto_path=$(SRC_DIR)/historian --python_out=$(SRC_DIR) --grpc_python_out=$(SRC_DIR) $(SRC_DIR)/historian/*.proto
	@echo "$(COLOR_GREEN)Protocol Buffers compilation complete$(COLOR_RESET)"

test-unit:
	@PYTHONPATH=src:src/historian ${MAMBA_DEV} pytest -v --durations=10 --junitxml=$(REPORTS_DIR)/tests.xml tests/
	@echo "$(COLOR_GREEN)Tests complete$(COLOR_RESET)"

test-experiments: experiment-wateringhole experiment-dnp experiment-modbus experiment-inverter-pivot
	@echo "$(COLOR_GREEN)All experiments complete$(COLOR_RESET)"

experiment-wateringhole:
	@cd $(SRC_DIR) && $(TEST_ENV) ${MAMBA_DEV} ${PYTHON} -m unittest discover controller "WateringHoleAttack.py" -v -k WateringHoleAttack 2>&1

experiment-dnp:
	@cd $(SRC_DIR) && $(TEST_ENV) ${MAMBA_DEV} ${PYTHON} -m unittest discover controller/dnp3 "DNP3Attack.py" -v 2>&1

experiment-modbus:
	@cd $(SRC_DIR) && $(TEST_ENV) ${MAMBA_DEV} ${PYTHON} -m unittest discover controller/modbus "ModbusAttack.py" -v 2>&1

experiment-inverter-pivot:
	@cd $(SRC_DIR) && $(TEST_ENV) ${MAMBA_DEV} ${PYTHON} -m unittest controller.modbus.InverterPivotAttack.InverterPivotAttack.test_inverter_pivot_attack -v 2>&1

clean:
	@echo "Cleaning up..."
	@rm -rf $(SRC_DIR)/__pycache__
	@rm -f $(SRC_DIR)/*.pyc
	@rm -f $(REPORTS_DIR)
	@rm -rf .pytest_cache
	@echo "$(COLOR_GREEN)Cleanup complete$(COLOR_RESET)"

# Error handling for missing environment files
environment-dev.yml:
	$(error "environment-dev.yml is missing")

environment.yml:
	$(error "environment.yml is missing")
