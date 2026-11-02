# PHP Audit Apps Portal

Browser launcher for the PHP audit container.

The portal reads a deployed copy of:

- `remote_linux_container/installed_php_applications/inventory.json`

It intentionally builds links from the current request hostname and each app's
inventory port. It does not trust `remote_host`, `base_urls`, or other stored
absolute URLs, because those can become stale after DHCP lease changes.

Default URL:

- `http://<current-container-ip>:19163/`

Deployment:

```bash
bash scripts/deploy_remote_service_portal.sh
```
