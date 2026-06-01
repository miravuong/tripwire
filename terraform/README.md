# Terraform — Vault setup for Tripwire

Manages Tripwire's HashiCorp Vault footprint as code, replacing the manual
`vault policy write` / AppRole-create steps from the project README:

- a **KV v2 secrets engine** at `secret/` (backing `secret/data/tripwire/*`)
- the **`tripwire` policy**, sourced verbatim from `../vault/policies/tripwire.hcl`
- the **AppRole auth backend** and **`tripwire` role** the service logs in with

The role's TTL defaults mirror `../vault/roles/tripwire-role.json` (1h / 4h / 24h,
20 SecretID uses). Once you adopt Terraform, this module is the source of truth
for the role; that JSON scaffold becomes reference only.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- A reachable Vault server and a token allowed to manage policies, auth methods,
  and mounts.

## Usage

```bash
cd terraform

# Same environment the README's Vault section already uses.
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=<a-token-allowed-to-manage-vault>

terraform init
terraform plan
terraform apply
```

If the `secret/` mount already exists (e.g. a dev-mode server, where it is
created by default), skip creating it:

```bash
terraform apply -var manage_secret_mount=false
```

## Getting a token for the app

`terraform output role_id` returns the RoleID. The RoleID is not a secret on its
own — pair it with a SecretID generated out of band so the SecretID never lands
in Terraform state:

```bash
vault write -f auth/approle/role/tripwire/secret-id
vault write auth/approle/login \
  role_id=$(terraform output -raw role_id) \
  secret_id=<secret-id>
```

## State & secrets

- State can contain sensitive values; the bundled `.gitignore` keeps `*.tfstate`
  and `*.tfvars` out of git. For shared use, configure a remote backend
  (S3 + DynamoDB lock, or Terraform Cloud) instead of local state.
- This module writes no tokens or SecretIDs. Provider auth comes entirely from
  `VAULT_ADDR` / `VAULT_TOKEN` in the environment.
