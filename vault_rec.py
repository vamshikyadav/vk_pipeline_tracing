import os
import csv
import hvac
from hvac.exceptions import InvalidPath

# ENV VARS
VAULT_ADDR = os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = os.getenv('VAULT_TOKEN')
ROOT_NAMESPACE = os.getenv('VAULT_NAMESPACE', '')  # leave blank for root

# Create Vault client
def get_client(namespace=None):
    return hvac.Client(
        url=VAULT_ADDR,
        token=VAULT_TOKEN,
        namespace=namespace or ROOT_NAMESPACE
    )

def list_namespaces(client):
    try:
        response = client.secrets.kv.v1.list_secrets(path='identity/namespace')
        return [item.strip('/') for item in response['data']['keys']]
    except Exception as e:
        print(f"[WARN] Could not list namespaces: {e}")
        return []

def get_kv_mounts(client):
    try:
        mounts = client.sys.list_mounted_secrets_engines()["data"]
    except Exception as e:
        print(f"[ERROR] Failed to list mounts in namespace {client.namespace}: {e}")
        return {}
    kv_mounts = {}
    for path, config in mounts.items():
        if config["type"] == "kv":
            version = config.get("options", {}).get("version", "1")
            kv_mounts[path] = int(version)
    return kv_mounts

def list_kv2(client, path, mount_point):
    try:
        response = client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)
        return response["data"]["keys"]
    except InvalidPath:
        return []

def read_kv2(client, path, mount_point):
    try:
        return client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)["data"]["data"]
    except Exception as e:
        return f"[ERROR] {str(e)}"

def list_kv1(client, full_path):
    try:
        response = client.secrets.kv.v1.list_secrets(path=full_path)
        return response["data"]["keys"]
    except InvalidPath:
        return []

def read_kv1(client, full_path):
    try:
        return client.secrets.kv.v1.read_secret(path=full_path)["data"]
    except Exception as e:
        return f"[ERROR] {str(e)}"

def crawl_kv(client, path, mount_point, kv_version, results, namespace):
    relative_path = path[len(mount_point):] if path.startswith(mount_point) else path
    relative_path = relative_path.strip("/")

    if kv_version == 2:
        keys = list_kv2(client, relative_path, mount_point.strip('/'))
        for key in keys:
            full_key = f"{path}{key}".strip('/')
            if key.endswith('/'):
                crawl_kv(client, f"{full_key}/", mount_point, kv_version, results, namespace)
            else:
                data = read_kv2(client, full_key[len(mount_point):].strip('/'), mount_point.strip('/'))
                results.append((namespace, full_key, data))
    else:
        keys = list_kv1(client, path)
        for key in keys:
            full_key = f"{path}{key}".strip('/')
            if key.endswith('/'):
                crawl_kv(client, f"{full_key}/", mount_point, kv_version, results, namespace)
            else:
                data = read_kv1(client, full_key)
                results.append((namespace, full_key, data))

def write_to_csv(results, filename="vault_secrets.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Namespace", "Path", "Key", "Value"])
        for namespace, path, data in results:
            if isinstance(data, dict):
                for key, value in data.items():
                    writer.writerow([namespace, path, key, value])
            else:
                writer.writerow([namespace, path, "", data])

def main():
    all_results = []

    root_client = get_client()
    if not root_client.is_authenticated():
        print("Vault authentication failed.")
        return

    # Get sub-namespaces under root
    namespaces = list_namespaces(root_client)
    if ROOT_NAMESPACE:
        namespaces = [ROOT_NAMESPACE + ns for ns in namespaces]
    namespaces.insert(0, ROOT_NAMESPACE)  # Include root namespace

    for ns in namespaces:
        ns_display = ns or "[root]"
        print(f"\n🚀 Crawling namespace: {ns_display}")
        client = get_client(ns)

        kv_mounts = get_kv_mounts(client)
        for mount_point, version in kv_mounts.items():
            print(f"  → Mount: {mount_point} (KV v{version})")
            crawl_kv(client, mount_point, mount_point, version, all_results, ns or "/")

    write_to_csv(all_results)
    print("\n✅ Done. Secrets saved to vault_secrets.csv")

if __name__ == "__main__":
    main()
