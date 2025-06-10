import os
import hvac
from hvac.exceptions import InvalidPath

# Setup Vault client
client = hvac.Client(
    url=os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200'),
    token=os.getenv('VAULT_TOKEN'),
    namespace=os.getenv('VAULT_NAMESPACE', None),
)

def get_kv_version_and_mounts():
    mounts = client.sys.list_mounted_secrets_engines()["data"]
    kv_mounts = {}
    for mount_path, config in mounts.items():
        if config["type"] == "kv":
            version = config.get("options", {}).get("version", "1")
            kv_mounts[mount_path] = int(version)
    return kv_mounts

def list_kv2(path, mount_point):
    try:
        response = client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)
        return response["data"]["keys"]
    except InvalidPath:
        return []

def read_kv2(path, mount_point):
    try:
        return client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)["data"]["data"]
    except Exception as e:
        return f"[ERROR] {str(e)}"

def list_kv1(full_path):
    try:
        response = client.secrets.kv.v1.list_secrets(path=full_path)
        return response["data"]["keys"]
    except InvalidPath:
        return []

def read_kv1(full_path):
    try:
        return client.secrets.kv.v1.read_secret(path=full_path)["data"]
    except Exception as e:
        return f"[ERROR] {str(e)}"

def crawl_kv(path, mount_point, kv_version, results):
    relative_path = path[len(mount_point):] if path.startswith(mount_point) else path
    relative_path = relative_path.strip("/")

    if kv_version == 2:
        keys = list_kv2(relative_path, mount_point.strip('/'))
        for key in keys:
            full_key = f"{path}{key}".strip('/')
            if key.endswith('/'):
                crawl_kv(f"{full_key}/", mount_point, kv_version, results)
            else:
                results[full_key] = read_kv2(full_key[len(mount_point):].strip('/'), mount_point.strip('/'))
    else:
        keys = list_kv1(path)
        for key in keys:
            full_key = f"{path}{key}".strip('/')
            if key.endswith('/'):
                crawl_kv(f"{full_key}/", mount_point, kv_version, results)
            else:
                results[full_key] = read_kv1(full_key)

def main():
    if not client.is_authenticated():
        print("Vault authentication failed.")
        return

    kv_mounts = get_kv_version_and_mounts()
    all_results = {}

    for mount_point, version in kv_mounts.items():
        print(f"Crawling mount: {mount_point} (KV v{version})")
        crawl_kv(mount_point, mount_point, version, all_results)

    for path, value in all_results.items():
        print(f"{path} → {value}")

if __name__ == "__main__":
    main()
