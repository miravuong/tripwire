# Authenticates via the VAULT_ADDR and VAULT_TOKEN environment variables — the
# same ones the README's `export VAULT_ADDR` / `vault login` flow already sets.
# Never hardcode an address or token here; tokens must not live in source or state.
provider "vault" {
  # A null value leaves `address` unset so the provider falls back to $VAULT_ADDR.
  address = var.vault_address
}
