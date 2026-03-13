path "secret/data/tripwire/*" {
  capabilities = ["create", "update", "read", "delete", "list"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
