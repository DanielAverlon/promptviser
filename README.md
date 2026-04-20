# promptviser

LLM Prompt Adviser

### Client config

    cat ~/.config/promptviser/config.yaml

```yaml
---
clients:
  local_wfe:
    host: https://0.0.0.0:7880
    tls:
      cert: /tmp/promptviser/certs/promptviser_admin.pem
      key: /tmp/promptviser/certs/promptviser_admin.key
      trusted_ca: /tmp/promptviser/certs/trusty_root_ca.pem
    request:
      retry_limit: 3
      timeout: 6s
    storage_folder: ~/.config/promptviser
```
