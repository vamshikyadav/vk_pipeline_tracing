import hvac
import csv
import os
from urllib.parse import urljoin

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

def is_kv_v2(mount_path):
    try:
        secret_config = client.secrets.kv.v2.read_configuration(mount_point=mount_path.rstrip('/'))
        return True
    except Exception:
        return False

def list_secrets_recursively(mount_path, path="", is_v2=False):
    secrets = []
    list_func = client.secrets.kv.v2.list_secrets if is_v2 else client.secrets.kv.v1.list_secrets

    try:
        keys = list_func(path=path, mount_point=mount_path.rstrip('/'))['data']['keys']
    except Exception:
        return secrets

    for key in keys:
        if key.endswith("/"):
            secrets += list_secrets_recursively(mount_path, path + key, is_v2)
        else:
            secrets.append((mount_path, path + key))
    return secrets

def list_subnamespaces(namespace):
    namespaces = [namespace]
    try:
        headers = {'X-Vault-Namespace': namespace} if namespace else {}
        response = client.adapter.get('/v1/sys/namespaces', headers=headers)
        sub_ns = response.json().get('data', {}).get('keys', [])
        for ns in sub_ns:
            full_ns = f"{namespace}/{ns}".strip("/")
            namespaces.extend(list_subnamespaces(full_ns))
    except Exception:
        pass
    return namespaces

def get_mounts(namespace):
    headers = {'X-Vault-Namespace': namespace} if namespace else {}
    response = client.adapter.get('/v1/sys/mounts', headers=headers)
    mounts = response.json()
    return [m for m in mounts if mounts[m]['type'] == 'kv']

def export_secrets_to_csv(root_namespace=""):
    all_namespaces = list_subnamespaces(root_namespace)
    with open('vault_secrets.csv', 'w', newline='') as csvfile:
        fieldnames = ['Namespace', 'Mount Path', 'Secret Path', 'KV Version']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for namespace in all_namespaces:
            print(f"🔍 Checking namespace: {namespace}")
            headers = {'X-Vault-Namespace': namespace} if namespace else {}
            mounts = get_mounts(namespace)

            for mount in mounts:
                mount_path = mount
                is_v2 = is_kv_v2(mount_path)
                secrets = list_secrets_recursively(mount_path, is_v2=is_v2)

                for mount_path, secret_path in secrets:
                    writer.writerow({
                        'Namespace': namespace,
                        'Mount Path': mount_path,
                        'Secret Path': secret_path,
                        'KV Version': 'v2' if is_v2 else 'v1'
                    })

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Export Vault secrets to CSV.')
    parser.add_argument('--namespace', type=str, help='Root Vault namespace', default="")
    args = parser.parse_args()
    export_secrets_to_csv(args.namespace)
