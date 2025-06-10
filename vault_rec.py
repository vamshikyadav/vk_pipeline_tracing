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


def list_all_secret_paths(mount_path, namespace, current_path="", is_v2=False):
    headers = {"X-Vault-Namespace": namespace} if namespace else {}
    secrets = []

    if is_v2:
        list_url = f"/v1/{mount_path}metadata/{current_path}".rstrip("/") + "?list=true"
    else:
        list_url = f"/v1/{mount_path}{current_path}".rstrip("/") + "?list=true"

    try:
        response = client.adapter.get(list_url, headers=headers)
        keys = response.json()["data"]["keys"]
    except Exception:
        return secrets

    for key in keys:
        full_path = f"{current_path}{key}"
        if key.endswith("/"):
            # Recurse into subfolder
            secrets += list_all_secret_paths(mount_path, namespace, full_path, is_v2)
        else:
            secrets.append(full_path)

    return secrets


def get_kv_mounts():
    headers = {"X-Vault-Namespace": VAULT_NAMESPACE} if VAULT_NAMESPACE else {}
    try:
        response = client.adapter.get("/v1/sys/mounts", headers=headers)
        mounts = response.json()
        return [m for m in mounts if mounts[m].get("type") == "kv"]
    except Exception as e:
        print(f"❌ Could not get mounts: {e}")
        return []


def export_to_csv():
    mounts = get_kv_mounts()

    with open("vault_secrets.csv", "w", newline="") as csvfile:
        fieldnames = ["Namespace", "Mount Path", "Secret Path", "KV Version"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for mount in mounts:
            try:
                is_v2 = is_kv_v2(mount)
                print(f"🔍 Scanning mount: {mount} ({'v2' if is_v2 else 'v1'})")
                paths = list_all_secret_paths(mount, VAULT_NAMESPACE, "", is_v2)

                for secret_path in paths:
                    writer.writerow({
                        "Namespace": VAULT_NAMESPACE or "root",
                        "Mount Path": mount,
                        "Secret Path": secret_path,
                        "KV Version": "v2" if is_v2 else "v1"
                    })
            except Exception as e:
                print(f"⚠️ Skipping mount {mount} due to error: {e}")


if __name__ == "__main__":
    export_to_csv()
