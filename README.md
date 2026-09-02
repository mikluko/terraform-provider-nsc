# Terraform NSC Provider

Terraform provider for managing NATS JWT authentication tokens and related resources. Named after the [nsc](https://docs.nats.io/using-nats/nats-tools/nsc) (NATS Security and Configuration) CLI tool.

## Features

- Generate and manage NATS Operator, Account, and User JWTs
- All keys and JWTs stored in Terraform state (compatible with Terraform Cloud)
- Basic permission model with allow/deny for publish and subscribe
- Support for bearer tokens and response permissions
- Account resource limits (connections, data, payload, subscriptions)
- JetStream limits configuration (storage, streams, consumers)
- Account imports and exports for cross-account communication
- Account-level subject mappings, including weighted destinations and mapping functions such as `partition`
- Automatic generation of user credential files

### Future Enhancements

- **Signing Key Management**: Key rotation and revocation support
- **File-based Resolver**: Support for file-based JWT resolution

## Versioning

This project uses [EffVer (Intended Effort Versioning)](https://jacobtomlinson.dev/effver/) for version management.

EffVer communicates the expected effort for users to adopt a new version, rather than the type of changes made.

### Version Format: `MACRO.MESO.MICRO`

- **MACRO**: Significant effort required - major breaking changes or overhauls
- **MESO**: Some effort required - minor breaking changes or larger features
- **MICRO**: No effort required - small fixes or features

### Next Version Guidelines

When choosing the next version number, consider the effort required by users:

1. **Increment MICRO** when:
   - Fixing bugs that don't change behavior
   - Adding small features that are fully backward compatible
   - Documentation improvements
   - Performance optimizations with no API changes
   - **Users can upgrade without any changes**

2. **Increment MESO** when:
   - Adding new resources or data sources (users may want to adopt them)
   - Changing default values
   - Deprecating features (not removing)
   - Minor breaking changes with clear migration paths
   - **Users may need small adjustments or testing**

3. **Increment MACRO** when:
   - Removing resources, attributes, or features
   - Major architectural changes
   - Changes requiring manual state migration
   - Incompatible provider configuration changes
   - **Users need significant time and effort to upgrade**

## Architecture Decision Records

Important design decisions are documented in the `docs/adr/` directory. These ADRs explain key architectural choices and trade-offs:

- [ADR-001](docs/adr/001-system-account-creation-strategy.md) - System Account Creation Strategy (Superseded)
- [ADR-002](docs/adr/002-system-account-reference-strategy.md) - System Account Reference Strategy (Superseded)
- [ADR-003](docs/adr/003-system-account-circular-dependency-resolution.md) - System Account Circular Dependency Resolution (Current)

Please review these documents to understand the design philosophy and decision rationale.

## Development

### Requirements

- Go 1.25+
- Terraform 1.0+
- nsc (optional, for generating test keys)

### Building

```bash
go build -o terraform-provider-nsc
```

### Testing

#### Generate Test Operator Seed

For integration tests, you need an operator seed. Generate one using either method:

**Using nkeys tool:**

```bash
# Install nkeys if needed
go install github.com/nats-io/nkeys/nk@latest

# Generate operator keypair
nk -gen operator
```

**Using nsc:**

```bash
# Install nsc if needed
brew install nats-io/nats-tools/nsc

# Generate operator nkey
nsc generate nkey --operator
```

Copy the seed (starts with `SO`) to `.envrc`:

```bash
cp .envrc.example .envrc
# Edit .envrc and add your operator seed
export NATSJWT_TEST_OPERATOR_SEED="SO..."
```

#### Run Tests

```bash
# Unit tests
go test ./...

# Integration tests (requires NATSJWT_TEST_OPERATOR_SEED)
TF_ACC=1 go test ./internal/provider -v

# Specific test
TF_ACC=1 go test ./internal/provider -v -run TestIntegration_ProviderPush
```

### Provider Configuration

The provider requires no configuration:

```hcl
provider "natsjwt" {
  # No configuration required
}
```

## Usage Examples

### Basic JWT Generation

```hcl
# Create operator
resource "nsc_operator" "main" {
  name                 = "MyOperator"
  generate_signing_key = true
}

# Create account
resource "nsc_account" "app" {
  name          = "AppAccount"
  operator_seed = nsc_operator.main.seed

  allow_pub = [ "app.>" ]
  allow_sub = [ "app.>", "_INBOX.>" ]
}

# Create user
resource "nsc_user" "client" {
  name         = "app-client"
  account_seed = nsc_account.app.seed

  allow_pub = [ "app.requests.>" ]
  allow_sub = [ "app.responses.>", "_INBOX.>" ]

  # Optional user-level limits
  max_subscriptions = 100       # Max number of subscriptions
  max_data          = 104857600 # 100MB max data per day
  max_payload       = 1048576   # 1MB max message size

  # Connection type restrictions (optional)
  # Valid types: STANDARD, WEBSOCKET, LEAFNODE, LEAFNODE_WS, MQTT, MQTT_WS, IN_PROCESS
  allowed_connection_types = ["STANDARD", "WEBSOCKET"]
}
```

### With System Account User

```hcl
# Operator includes integrated system account
resource "nsc_operator" "main" {
  name                  = "MyOperator"
  generate_signing_key  = true
  create_system_account = true
}

# Create a user in the system account for monitoring
resource "nsc_user" "sys_admin" {
  name         = "sys_admin"
  account_seed = nsc_operator.main.system_account_seed

  # Full permissions for system monitoring
  allow_pub = [">"]
  allow_sub = [">"]
}

# Create application account
resource "nsc_account" "app" {
  name          = "AppAccount"
  operator_seed = nsc_operator.main.seed

  allow_pub = ["app.>"]
  allow_sub = ["app.>", "_INBOX.>"]
}
```

## Import

Resources support import using the format `name/seed` or `name/seed/parent_seed`:

```bash
# Import operator
terraform import nsc_operator.main "MyOperator/SO..."

# Import account
terraform import nsc_account.app "AppAccount/SA.../SO..."

# Import user
terraform import nsc_user.client "app-client/SU.../SA..."
```

## Security Considerations

- Seeds and JWTs are stored in Terraform state - ensure state is encrypted and secured
- Use environment variables or secure secret management for sensitive values
- The provider supports Terraform Cloud's remote state storage
- System account is created automatically with operator when `create_system_account = true`
- Regular accounts should use appropriate allow/deny lists for security
- Consider using signing keys for easier key rotation in the future
