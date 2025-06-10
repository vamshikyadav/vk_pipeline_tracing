import hvac
import os
import csv

VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE", "")

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)


def is_kv_v2(mount_path):
    try:
        client.secrets.kv.v2.read_configuration(mount_point=mount_path.rstrip('/'))
        return True
    except Exception:
        return False


def list_secrets_recursively(mount_path, path="", is_v2=False):
    secrets = []
    headers = {"X-Vault-Namespace": VAULT_NAMESPACE} if VAULT_NAMESPACE else {}

    try:
        if is_v2:
            endpoint = f"/v1/{mount_path}metadata/{path}".rstrip("/") + "?list=true"
        else:
            endpoint = f"/v1/{mount_path}{path}".rstrip("/") + "?list=true"

        response = client.adapter.get(endpoint, headers=headers)
        keys = response.json()["data"]["keys"]
    except Exception:
        return secrets

    for key in keys:
        if key.endswith("/"):
            secrets += list_secrets_recursively(mount_path, path + key, is_v2)
        else:
            secrets.append(path + key)
    return secrets


def get_kv_mounts():
    headers = {"X-Vault-Namespace": VAULT_NAMESPACE} if VAULT_NAMESPACE else {}
    try:
        response = client.adapter.get("/v1/sys/mounts", headers=headers)
        mounts = response.json()
        return [m for m in mounts if mounts[m].get("type") == "kv"]
    except Exception as e:
        print(f"Could not fetch mounts: {e}")
        return []


def export_to_csv():
    mounts = get_kv_mounts()
    with open("vault_secrets.csv", "w", newline="") as csvfile:
        fieldnames = ["Namespace", "Mount Path", "Secret Path", "KV Version"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for mount in mounts:
            is_v2 = is_kv_v2(mount)
            print(f"Scanning: {mount} ({'v2' if is_v2 else 'v1'})")

            secrets = list_secrets_recursively(mount, "", is_v2)
            for secret in secrets:
                writer.writerow({
                    "Namespace": VAULT_NAMESPACE or "root",
                    "Mount Path": mount,
                    "Secret Path": secret,
                    "KV Version": "v2" if is_v2 else "v1"
                })


if __name__ == "__main__":
    export_to_csv()
