# OAK Runner

*Automate complex API workflows with simple YAML definitions*

OAK Runner is a powerful workflow-execution engine that turns complex API orchestration into concise, declarative YAML workflows.
Built on the **Arazzo** specification, it lets you chain API calls, handle authentication, manage data flow and implement sophisticated business logic—without writing code.

---

## Table of Contents

* [Why OAK Runner?](#why-oak-runner)
* [Key Features](#key-features)
* [Use Cases](#use-cases)
* [Installation](#installation)

  * [Quick Start with `uvx`](#quick-start-with-uvx-recommended)
  * [Development Install with Make](#development-installation-with-make)
  * [Python Package](#python-package)
* [Quick Start](#quick-start)

  1. [Create Your First Workflow](#1-create-your-first-workflow)
  2. [Execute the Workflow](#2-execute-the-workflow)
  3. [Use in Python](#3-use-in-python)
* [Development Workflow](#development-workflow)
* [Core Concepts](#core-concepts)
* [Comprehensive Examples](#comprehensive-examples)
* [Project Structure](#project-structure)
* [Adding New Features](#adding-new-features)
* [Authentication Guide](#authentication-guide)
* [Server Configuration](#server-configuration)
* [CLI Reference](#cli-reference)
* [Testing Framework](#testing-framework)
* [Contributing](#contributing)
* [License](#license)
* [Acknowledgments](#acknowledgments)

---

## Why OAK Runner?

### Before OAK Runner

```python
auth_response = requests.post('/auth', data={'username': user, 'password': pwd})
token = auth_response.json()['access_token']

user_response = requests.get('/users/me', headers={'Authorization': f'Bearer {token}'})
user_id      = user_response.json()['id']

orders_response = requests.get(f'/users/{user_id}/orders',
                               headers={'Authorization': f'Bearer {token}'})
# Handle errors, retries, conditional logic...
```

### With OAK Runner

```yaml
workflows:
  - workflowId: getUserOrders
    steps:
      - stepId: authenticate
        operationId: login
        parameters:
          - name: username
            value: $inputs.username
          - name: password
            value: $inputs.password

      - stepId: getUser
        operationId: getCurrentUser
        parameters:
          - name: Authorization
            in: header
            value: Bearer $steps.authenticate.outputs.access_token

      - stepId: getOrders
        operationId: getUserOrders
        parameters:
          - name: userId
            value: $steps.getUser.outputs.id
          - name: Authorization
            in: header
            value: Bearer $steps.authenticate.outputs.access_token
```

---

## Key Features

* **API Workflow Orchestration** – Chain multiple API calls with automatic data flow between steps
* **Smart Authentication** – Built-in handling for OAuth2, API keys, HTTP Basic/Bearer, …
* **Data Transformation** – Extract & transform data using JSONPath, JSON Pointer and expressions
* **Flow Control** – Conditional execution, retries, error handling and branching logic
* **Multi-API Support** – Orchestrate workflows across different services
* **Testing Framework** – Built-in testing and validation for workflows
* **Standards-Based** – Powered by **OpenAPI 3+** and the **Arazzo** spec

---

## Use Cases

* **API Integration Pipelines** – Synchronise data between services
* **E-commerce Workflows** – Order processing, inventory management, payment flows
* **DevOps Automation** – CI/CD pipelines, infrastructure provisioning
* **Data Collection** – Aggregate data from multiple APIs
* **Business Process Automation** – Customer onboarding, approval workflows

---

## Installation

### Quick Start with `uvx` (recommended)

```bash
uvx oak-runner --help
# execute a workflow
uvx oak-runner execute-workflow workflow.arazzo.yaml --workflow-id myWorkflow
```

### Development Installation with Make

```bash
git clone https://github.com/jentic/oak.git
cd oak/tools/oak-runner

# one-time setup (uv + venv + PDM + deps)
make setup

# test the CLI immediately
make run
```

Run the full test-suite:

```bash
make test
```

See all available commands:

```bash
make help
```

### Python Package

```bash
pip install oak-runner
```

---

## Quick Start

### 1. Create Your First Workflow

Save as **`petstore-workflow.arazzo.yaml`**:

```yaml
arazzo: 1.0.0
info:
  title: Pet Store Workflow
  version: 1.0.0

sourceDescriptions:
  - name: petstore
    url: https://petstore3.swagger.io/api/v3/openapi.json
    type: openapi

workflows:
  - workflowId: findAvailablePets
    summary: Find all available pets in the store
    inputs:
      type: object
      properties:
        status:
          type: string
          default: available

    steps:
      - stepId: getPets
        description: Get pets by status
        operationId: findPetsByStatus
        parameters:
          - name: status
            in: query
            value: $inputs.status

        outputs:
          availablePets: $response.body
          petCount:     $response.body.length

    outputs:
      pets:  $steps.getPets.outputs.availablePets
      count: $steps.getPets.outputs.petCount
```

### 2. Execute the Workflow

```bash
# list available workflows
uvx oak-runner list-workflows petstore-workflow.arazzo.yaml

# run it
uvx oak-runner execute-workflow petstore-workflow.arazzo.yaml \
  --workflow-id findAvailablePets \
  --inputs '{"status": "available"}'
```

Check auth requirements:

```bash
uvx oak-runner show-env-mappings petstore-workflow.arazzo.yaml
```

### 3. Use in Python

```python
from oak_runner import OAKRunner

runner = OAKRunner.from_arazzo_path("petstore-workflow.arazzo.yaml")
result  = runner.execute_workflow(
    workflow_id="findAvailablePets",
    inputs={"status": "available"}
)
print(f"Found {result.outputs['count']} pets")
```

---

## Development Workflow

The included **Makefile** automates the entire dev-experience—no extra tooling required.

```bash
# bootstrap everything
make setup

# run CLI with default args
make run

# run with custom args
make run RUN_ARGS="list-workflows examples/petstore.arazzo.yaml"
```

Common targets:

| Command           | Purpose                            |
| ----------------- | ---------------------------------- |
| `make test`       | Run tests with coverage            |
| `make test-fast`  | Quick tests (no coverage)          |
| `make format`     | Auto-format code with Ruff + isort |
| `make lint`       | Linters & type checks              |
| `make clean`      | Remove caches & artefacts          |
| `make pre-commit` | Format + lint + test in one go     |

---

## Core Concepts

### Workflows & Steps

```yaml
workflows:
  - workflowId: userRegistration
    steps:
      - stepId: createUser
        operationId: createUser
        parameters:
          - name: email
            value: $inputs.email

      - stepId: sendWelcomeEmail
        operationId: sendEmail
        parameters:
          - name: to
            value: $steps.createUser.outputs.email
          - name: template
            value: welcome
```

### Data Flow with Expressions

* Input value   `$inputs.userId`
* Previous step  `$steps.loginStep.outputs.accessToken`
* JSON Pointer  `$response.body#/data/items/0/id`
* Array access  `$steps.searchStep.outputs.results[0].name`

### Authentication Management

```bash
uvx oak-runner show-env-mappings my-workflow.arazzo.yaml
```

### Conditional Logic & Flow Control

```yaml
steps:
  - stepId: checkUserStatus
    operationId: getUser
    successCriteria:
      - condition: $response.body.status == "active"

    onSuccess:
      - name: continueWorkflow
        type: goto
        stepId: processActiveUser

    onFailure:
      - name: handleInactive
        type: goto
        stepId: sendActivationEmail
```

---

## Comprehensive Examples

### E-commerce Order Processing

```yaml
workflows:
  - workflowId: processOrder
    inputs:
      type: object
      properties:
        cartId:        { type: string }
        paymentMethod: { type: string }

    steps:
      - stepId: validateCart
        operationId: getCart
        parameters:
          - name: cartId
            value: $inputs.cartId
        successCriteria:
          - condition: $response.body.items.length > 0

      - stepId: calculateTax
        operationId: calculateTax
        parameters:
          - name: items
            value: $steps.validateCart.outputs.items
          - name: shippingAddress
            value: $steps.validateCart.outputs.shippingAddress

      - stepId: processPayment
        operationId: chargePayment
        parameters:
          - name: amount
            value: $steps.calculateTax.outputs.totalAmount
          - name: paymentMethod
            value: $inputs.paymentMethod

        onSuccess:
          - name: createOrder
            type: goto
            stepId: createOrder

        onFailure:
          - name: handlePaymentFailure
            type: end
```

### Multi-Service Data Aggregation

```yaml
workflows:
  - workflowId: generateUserReport
    steps:
      - stepId: getUserProfile
        operationId: getUser

      - stepId: getUserOrders
        operationId: getUserOrders
        parameters:
          - name: userId
            value: $steps.getUserProfile.outputs.id

      - stepId: getUserPreferences
        operationId: getUserPreferences
        parameters:
          - name: userId
            value: $steps.getUserProfile.outputs.id

      - stepId: aggregateData
        operationId: createReport
        requestBody:
          contentType: application/json
          payload:
            userId:      $steps.getUserProfile.outputs.id
            profile:     $steps.getUserProfile.outputs
            orders:      $steps.getUserOrders.outputs
            preferences: $steps.getUserPreferences.outputs
```

---

## Project Structure

```text
oak-runner/
├── Makefile                  # Dev automation
├── src/oak_runner/           # Main package
│   ├── auth/                 # Authentication
│   ├── executor/             # Step engine
│   ├── extractor/            # Data helpers
│   ├── models.py             # Core models
│   ├── runner.py             # OAKRunner class
│   └── evaluator.py          # Expression eval
├── tests/                    # Unit, integration, e2e
├── examples/                 # Example workflows
├── arazzo_spec/              # Arazzo spec
└── pyproject.toml            # PDM config
```

---

## Adding New Features

1. **Write tests first**

   ```bash
   make test-fast
   ```
2. **Implement the feature**

   ```bash
   make run RUN_ARGS="--help"
   ```
3. **Format & Lint**

   ```bash
   make format
   make lint
   ```
4. **Run full test suite**

   ```bash
   make test
   ```
5. **Pre-commit validation**

   ```bash
   make pre-commit
   ```

---

## Authentication Guide

### API Key Authentication

```bash
export MYAPI_API_KEY='your-api-key-here'
```

### OAuth2 Client Credentials

```bash
export MYAPI_OAUTH_CLIENT_ID='your-client-id'
export MYAPI_OAUTH_CLIENT_SECRET='your-client-secret'
```

### HTTP Basic / Bearer

```bash
export MYAPI_USERNAME='your-username'
export MYAPI_PASSWORD='your-password'
# or
export MYAPI_TOKEN='your-bearer-token'
```

### Discovering Requirements

```bash
uvx oak-runner show-env-mappings workflow.arazzo.yaml
```

Example output:

```json
{
  "auth": {
    "petstore_api": {
      "apiKey": "PETSTORE_API_KEY"
    }
  },
  "servers": {
    "https://{environment}.api.example.com": {
      "environment": "EXAMPLE_OAK_SERVER_ENVIRONMENT"
    }
  }
}
```

---

## Server Configuration

```yaml
servers:
  - url: "https://{environment}.api.example.com/{version}"
    variables:
      environment:
        default: prod
        enum: [dev, staging, prod]
      version:
        default: v1
```

Set via environment variables:

```bash
export MYAPI_OAK_SERVER_ENVIRONMENT='staging'
export MYAPI_OAK_SERVER_VERSION='v2'
```

CLI override:

```bash
uvx oak-runner execute-workflow workflow.arazzo.yaml \
  --workflow-id myWorkflow \
  --server-variables '{"MYAPI_OAK_SERVER_ENVIRONMENT": "dev"}'
```

---

## CLI Reference

### Workflow Management

```bash
uvx oak-runner list-workflows workflow.arazzo.yaml
uvx oak-runner describe-workflow workflow.arazzo.yaml --workflow-id myWorkflow
uvx oak-runner generate-example workflow.arazzo.yaml --workflow-id myWorkflow
```

### Execution

```bash
uvx oak-runner execute-workflow workflow.arazzo.yaml \
  --workflow-id myWorkflow \
  --inputs '{"param1": "value1"}' \
  --server-variables '{}'

uvx oak-runner execute-operation \
  --openapi-path spec.json \
  --operation-id getUser \
  --inputs '{"userId": "123"}'
```

### Configuration

```bash
uvx oak-runner show-env-mappings workflow.arazzo.yaml
uvx oak-runner show-env-mappings --openapi-path spec.json
# or via Makefile
make show-env ARAZZO_FILE=workflow.arazzo.yaml
```

### Global Options

| Option                                            | Meaning               |
| ------------------------------------------------- | --------------------- |
| `--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}` | Set logging verbosity |
| `--help`                                          | Show command help     |

---

## Testing Framework

```bash
make test          # all tests with coverage
make test-unit     # unit tests only
make test-integration
make test-e2e
make test-fast     # quick dev loop
```

In Python:

```python
from oak_runner.testing import WorkflowTester

tester = WorkflowTester("workflow.arazzo.yaml")
tester.mock_response("getUserById", {"id": "123", "name": "John"})

result = tester.execute_workflow("myWorkflow", {"userId": "123"})
assert result.status == "success"
assert tester.call_count("getUserById") == 1
```

See **tests/README.md** for details.

---

## Contributing

We welcome contributions!

```bash
# Setup
make setup

# Create feature branch
git checkout -b feature/amazing-feature

# Dev loop
make run
make test-fast
make format
make lint

# Final checks
make pre-commit

# Build for distribution
make build
```

Open issues or start discussions on GitHub.

---

## License

Released under the **MIT License** – see **LICENSE** for details.

---

## Acknowledgments

* Built on the **Arazzo** specification
* Powered by **OpenAPI**
* Inspired by modern API-workflow orchestration patterns

---

Ready to automate your API workflows? **Run `make setup` or `uvx oak-runner --help` and dive into the examples!**
