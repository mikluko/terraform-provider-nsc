# Generate keys
resource "nsc_nkey" "operator" {
  type = "operator"
}

resource "nsc_nkey" "account" {
  type = "account"
}

# Create operator
resource "nsc_operator" "main" {
  name        = "MyOperator"
  subject     = nsc_nkey.operator.public_key
  issuer_seed = nsc_nkey.operator.seed
}

# Account with subject mappings, applied by the server to every publish
resource "nsc_account" "mapped" {
  name        = "MappedAccount"
  subject     = nsc_nkey.account.public_key
  issuer_seed = nsc_nkey.operator.seed

  # Partition a subject on its wildcard token: orders.<id> is rewritten to
  # orders.<id>.<0..15>, so sixteen JetStream streams can each capture one slice
  mapping {
    subject = "orders.*"
    destination {
      subject = "orders.{{wildcard(1)}}.{{partition(16,1)}}"
    }
  }

  # Weighted routing: nine in ten requests stay on the stable subject
  mapping {
    subject = "requests.search"
    destination {
      subject = "requests.search.stable"
      weight  = 90
    }
    destination {
      subject = "requests.search.canary"
      weight  = 10
    }
  }
}
