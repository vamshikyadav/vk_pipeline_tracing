import hvac
import os

# Initialize Vault client
client = hvac.Client(
    url=os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200'),
    token=os.getenv('VAULT_TOKEN')
)

# Change this to your mount point (e.g., secret/)
MOUNT_POINT = "secret"

def is_kv_v2(mount_point):
    mounts = client.sys.list_mounted_secrets_engines()
    mount_config = mounts.get(f"{mount_point}/")
    return mount_config and mount_config["options"].get("version") == "2"

def list_secrets_recursive(path, mount_point="secret"):
    try:
        list_response = client.secrets.kv.v2.list_secrets(
            path=path,
            mount_point=mount_point
        )
    except hvac.exceptions.InvalidPath:
        return []

    secrets = list_response.get("data", {}).get("keys", [])
    all_results = {}

    for key in secrets:
        full_path = f"{path}/{key}".strip('/')
        if key.endswith('/'):
            # Recurse into subdirectory
            nested_results = list_secrets_recursive(full_path, mount_point)
            all_results.update(nested_results)
        else:
            try:
                secret = client.secrets.kv.v2.read_secret_version(
                    path=full_path,
                    mount_point=mount_point
                )
                all_results[full_path] = secret['data']['data']
            except Exception as e:
                all_results[full_path] = f"[ERROR] {str(e)}"
    return all_results

if __name__ == "__main__":
    if not client.is_authenticated():
        print("Vault authentication failed. Check your VAULT_TOKEN.")
        exit(1)

    if not is_kv_v2(MOUNT_POINT):
        print(f"The mount point '{MOUNT_POINT}' is not using KV version 2.")
        exit(1)

    secrets = list_secrets_recursive("", mount_point=MOUNT_POINT)
    for path, value in secrets.items():
        print(f"{path} → {value}")
