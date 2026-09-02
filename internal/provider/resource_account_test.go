package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/nats-io/jwt/v2"
)

func TestAccAccountResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAccountResourceConfig("TestAccount"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "TestAccount"),
					resource.TestCheckResourceAttrSet("nsc_account.test", "subject"),
					resource.TestCheckResourceAttrSet("nsc_account.test", "jwt"),
					resource.TestCheckResourceAttrSet("nsc_account.test", "public_key"),
					testAccCheckAccountPublicKeyFormat("nsc_account.test", "public_key"),
					testAccCheckAccountPublicKeyFormat("nsc_account.test", "subject"),
				),
			},
			// Update and Read testing
			{
				Config: testAccAccountResourceConfig("UpdatedAccount"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "UpdatedAccount"),
				),
			},
		},
	})
}

func TestAccAccountResource_withLimits(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with limits
			{
				Config: testAccAccountResourceConfigWithLimits(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "LimitedAccount"),
					// Account limits
					resource.TestCheckResourceAttr("nsc_account.test", "max_connections", "100"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_leaf_nodes", "10"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_data", "1073741824"), // 1GB
					resource.TestCheckResourceAttr("nsc_account.test", "max_payload", "1048576"), // 1MB
					resource.TestCheckResourceAttr("nsc_account.test", "max_subscriptions", "1000"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_imports", "50"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_exports", "50"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_wildcard_exports", "false"),
					resource.TestCheckResourceAttr("nsc_account.test", "disallow_bearer_token", "true"),
					// JetStream limits
					resource.TestCheckResourceAttr("nsc_account.test", "max_memory_storage", "536870912"), // 512MB
					resource.TestCheckResourceAttr("nsc_account.test", "max_disk_storage", "10737418240"), // 10GB
					resource.TestCheckResourceAttr("nsc_account.test", "max_streams", "10"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_consumers", "100"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_ack_pending", "1000"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_memory_stream_bytes", "134217728"), // 128MB
					resource.TestCheckResourceAttr("nsc_account.test", "max_disk_stream_bytes", "1073741824"),  // 1GB
					resource.TestCheckResourceAttr("nsc_account.test", "max_bytes_required", "true"),
				),
			},
			// Update limits
			{
				Config: testAccAccountResourceConfigWithUpdatedLimits(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "LimitedAccount"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_connections", "200"),
					resource.TestCheckResourceAttr("nsc_account.test", "max_streams", "20"),
				),
			},
		},
	})
}

func TestAccAccountResource_withPermissions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with permissions
			{
				Config: testAccAccountResourceConfigWithPermissions(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "TestAccount"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_pub.#", "2"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_pub.0", "app.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_pub.1", "events.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_sub.#", "2"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_sub.0", "app.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_sub.1", "metrics.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "deny_pub.#", "1"),
					resource.TestCheckResourceAttr("nsc_account.test", "deny_pub.0", "admin.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "deny_sub.#", "1"),
					resource.TestCheckResourceAttr("nsc_account.test", "deny_sub.0", "secrets.>"),
				),
			},
			// Update permissions
			{
				Config: testAccAccountResourceConfigWithUpdatedPermissions(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "allow_pub.#", "1"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_pub.0", "public.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_sub.#", "1"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_sub.0", "public.>"),
				),
			},
		},
	})
}

func TestAccAccountResource_withResponsePermissions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with response permissions
			{
				Config: testAccAccountResourceConfigWithResponsePermissions(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "TestAccount"),
					resource.TestCheckResourceAttr("nsc_account.test", "allow_pub_response", "5"),
					resource.TestCheckResourceAttr("nsc_account.test", "response_ttl", "10s"),
				),
			},
		},
	})
}

func TestAccAccountResource_withExpiry(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with expiry
			{
				Config: testAccAccountResourceConfigWithExpiry("720h", "24h"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "expires_in", "720h"),
					resource.TestCheckResourceAttr("nsc_account.test", "starts_in", "24h"),
				),
			},
		},
	})
}

func TestAccAccountResource_withExports(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAccountResourceConfigWithExports(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "ExportAccount"),
					resource.TestCheckResourceAttr("nsc_account.test", "export.#", "2"),
					resource.TestCheckResourceAttr("nsc_account.test", "export.0.subject", "events.>"),
					resource.TestCheckResourceAttr("nsc_account.test", "export.0.type", "stream"),
					resource.TestCheckResourceAttr("nsc_account.test", "export.1.subject", "api.requests"),
					resource.TestCheckResourceAttr("nsc_account.test", "export.1.type", "service"),
					resource.TestCheckResourceAttr("nsc_account.test", "export.1.response_type", "Singleton"),
				),
			},
		},
	})
}

func TestAccAccountResource_withImports(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAccountResourceConfigWithImports(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.provider", "name", "ProviderAccount"),
					resource.TestCheckResourceAttr("nsc_account.consumer", "name", "ConsumerAccount"),
					resource.TestCheckResourceAttr("nsc_account.consumer", "import.#", "1"),
					resource.TestCheckResourceAttr("nsc_account.consumer", "import.0.subject", "shared.events.>"),
					resource.TestCheckResourceAttr("nsc_account.consumer", "import.0.type", "stream"),
					resource.TestCheckResourceAttr("nsc_account.consumer", "import.0.local_subject", "events.>"),
				),
			},
		},
	})
}

func TestAccAccountResource_withMappings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAccountResourceConfigWithMappings(90, 10),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "name", "MappingAccount"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.#", "2"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.0.subject", "orders.*"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.0.destination.#", "1"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.0.destination.0.subject", "orders.{{wildcard(1)}}.{{partition(16,1)}}"),
					resource.TestCheckNoResourceAttr("nsc_account.test", "mapping.0.destination.0.weight"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.1.subject", "requests.search"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.1.destination.#", "2"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.1.destination.0.weight", "90"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.1.destination.1.weight", "10"),
					testAccCheckAccountJWTMappings("nsc_account.test", map[string][]jwt.WeightedMapping{
						"orders.*": {
							{Subject: "orders.{{wildcard(1)}}.{{partition(16,1)}}"},
						},
						"requests.search": {
							{Subject: "requests.search.stable", Weight: 90},
							{Subject: "requests.search.canary", Weight: 10},
						},
					}),
				),
			},
			// Update the weights and confirm the re-signed JWT carries them
			{
				Config: testAccAccountResourceConfigWithMappings(50, 50),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.1.destination.0.weight", "50"),
					resource.TestCheckResourceAttr("nsc_account.test", "mapping.1.destination.1.weight", "50"),
					testAccCheckAccountJWTMappings("nsc_account.test", map[string][]jwt.WeightedMapping{
						"orders.*": {
							{Subject: "orders.{{wildcard(1)}}.{{partition(16,1)}}"},
						},
						"requests.search": {
							{Subject: "requests.search.stable", Weight: 50},
							{Subject: "requests.search.canary", Weight: 50},
						},
					}),
				),
			},
		},
	})
}

func TestAccAccountResource_rejectsOverweightMappings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAccountResourceConfigWithMappings(90, 20),
				ExpectError: regexp.MustCompile(`exceeds 100%`),
			},
		},
	})
}

func TestAccAccountResource_rejectsDuplicateMappingSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAccountResourceConfigWithDuplicateMappingSource(),
				ExpectError: regexp.MustCompile(`Duplicate mapping source`),
			},
		},
	})
}

func testAccAccountResourceConfigWithMappings(stableWeight, canaryWeight int) string {
	return fmt.Sprintf(`
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "MappingAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  mapping {
    subject = "orders.*"
    destination {
      subject = "orders.{{wildcard(1)}}.{{partition(16,1)}}"
    }
  }

  mapping {
    subject = "requests.search"
    destination {
      subject = "requests.search.stable"
      weight  = %[1]d
    }
    destination {
      subject = "requests.search.canary"
      weight  = %[2]d
    }
  }
}
`, stableWeight, canaryWeight)
}

func testAccAccountResourceConfigWithDuplicateMappingSource() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "MappingAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  mapping {
    subject = "orders.*"
    destination {
      subject = "orders.{{wildcard(1)}}.a"
    }
  }

  mapping {
    subject = "orders.*"
    destination {
      subject = "orders.{{wildcard(1)}}.b"
    }
  }
}
`
}

// testAccCheckAccountJWTMappings decodes the account JWT in state and checks the
// mappings it carries against want, source by source and destination by
// destination, comparing weights as nats-jwt reads them.
func testAccCheckAccountJWTMappings(resourceName string, want map[string][]jwt.WeightedMapping) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", resourceName)
		}

		claims, err := jwt.DecodeAccountClaims(rs.Primary.Attributes["jwt"])
		if err != nil {
			return fmt.Errorf("decode account JWT: %w", err)
		}
		if len(claims.Mappings) != len(want) {
			return fmt.Errorf("JWT carries %d mapping sources, want %d", len(claims.Mappings), len(want))
		}

		for source, destinations := range want {
			got, ok := claims.Mappings[jwt.Subject(source)]
			if !ok {
				return fmt.Errorf("JWT carries no mapping for source %q", source)
			}
			if len(got) != len(destinations) {
				return fmt.Errorf("mapping %q carries %d destinations, want %d", source, len(got), len(destinations))
			}
			for i := range destinations {
				if got[i].Subject != destinations[i].Subject ||
					got[i].GetWeight() != destinations[i].GetWeight() ||
					got[i].Cluster != destinations[i].Cluster {
					return fmt.Errorf("mapping %q destination %d is %+v, want %+v", source, i, got[i], destinations[i])
				}
			}
		}
		return nil
	}
}

func testAccAccountResourceConfig(name string) string {
	return fmt.Sprintf(`
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = %[1]q
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed
}
`, name)
}

func testAccAccountResourceConfigWithPermissions() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "TestAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  allow_pub = ["app.>", "events.>"]
  allow_sub = ["app.>", "metrics.>"]
  deny_pub  = ["admin.>"]
  deny_sub  = ["secrets.>"]
}
`
}

func testAccAccountResourceConfigWithUpdatedPermissions() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "TestAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  allow_pub = ["public.>"]
  allow_sub = ["public.>"]
}
`
}

func testAccAccountResourceConfigWithResponsePermissions() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name               = "TestAccount"
  subject            = nsc_nkey.account.public_key
  issuer_seed        = nsc_nkey.operator.seed
  allow_pub_response = 5
  response_ttl       = "10s"
}
`
}

func testAccAccountResourceConfigWithExpiry(expiry, start string) string {
	return fmt.Sprintf(`
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "TestAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed
  expires_in  = %[1]q
  starts_in   = %[2]q
}
`, expiry, start)
}

func testAccAccountResourceConfigWithLimits() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "LimitedAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  # Account limits
  max_connections    = 100
  max_leaf_nodes     = 10
  max_data           = 1073741824  # 1GB
  max_payload        = 1048576     # 1MB
  max_subscriptions  = 1000
  max_imports        = 50
  max_exports        = 50
  allow_wildcard_exports = false
  disallow_bearer_token  = true

  # JetStream limits
  max_memory_storage       = 536870912   # 512MB
  max_disk_storage         = 10737418240 # 10GB
  max_streams              = 10
  max_consumers            = 100
  max_ack_pending          = 1000
  max_memory_stream_bytes  = 134217728   # 128MB
  max_disk_stream_bytes    = 1073741824  # 1GB
  max_bytes_required       = true
}
`
}

func testAccAccountResourceConfigWithUpdatedLimits() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "LimitedAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  # Updated account limits
  max_connections    = 200  # Changed
  max_leaf_nodes     = 10
  max_data           = 1073741824
  max_payload        = 1048576
  max_subscriptions  = 1000
  max_imports        = 50
  max_exports        = 50
  allow_wildcard_exports = false
  disallow_bearer_token  = true

  # Updated JetStream limits
  max_memory_storage       = 536870912
  max_disk_storage         = 10737418240
  max_streams              = 20  # Changed
  max_consumers            = 100
  max_ack_pending          = 1000
  max_memory_stream_bytes  = 134217728
  max_disk_stream_bytes    = 1073741824
  max_bytes_required       = true
}
`
}

func testAccAccountResourceConfigWithExports() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "test" {
  name        = "ExportAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  export {
    subject = "events.>"
    type    = "stream"
    description = "Event stream export"
    advertise = true
  }

  export {
    subject = "api.requests"
    type    = "service"
    response_type = "Singleton"
    response_threshold = "5s"
    token_required = true
  }
}
`
}

func testAccAccountResourceConfigWithImports() string {
	return `
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "provider_account" {
  type = "account"
}

resource "nsc_nkey" "consumer_account" {
  type = "account"
}

resource "nsc_operator" "test" {
  name        = "TestOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "provider" {
  name        = "ProviderAccount"
  subject     = nsc_nkey.provider_account.public_key
  issuer_seed = nsc_nkey.operator.seed
}

resource "nsc_account" "consumer" {
  name        = "ConsumerAccount"
  subject     = nsc_nkey.consumer_account.public_key
  issuer_seed = nsc_nkey.operator.seed

  import {
    subject = "shared.events.>"
    account = nsc_account.provider.public_key
    type    = "stream"
    local_subject = "events.>"
  }
}
`
}

func testAccCheckAccountPublicKeyFormat(resourceName, attrName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", resourceName)
		}

		publicKey := rs.Primary.Attributes[attrName]
		if publicKey == "" {
			return fmt.Errorf("Public key attribute %s is empty", attrName)
		}

		// Check if it's a valid NATS account public key (starts with 'A')
		if !regexp.MustCompile(`^A[A-Z0-9]{55}$`).MatchString(publicKey) {
			return fmt.Errorf("Invalid account public key format: %s", publicKey)
		}

		return nil
	}
}
