import hvac
import csv
import os

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
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
    try:
        if is_v2:
            result = client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_path.rstrip('/'))
            keys = result["data"]["keys"]
        else:
            result = client.secrets.kv.v1.list_secrets(path=path, mount_point=mount_path.rstrip('/'))
            keys = result["data"]["keys"]
    except Exception:
        return secrets

    for key in keys:
        if key.endswith("/"):
            secrets += list_secrets_recursively(mount_path, path + key, is_v2)
        else:
            secrets.append(path + key)
    return secrets


def get_kv_mounts():
    try:
        headers = {"X-Vault-Namespace": VAULT_NAMESPACE} if VAULT_NAMESPACE else {}
        response = client.adapter.get("/v1/sys/mounts", headers=headers)
        data = response if isinstance(response, dict) else response.json()
        mounts = []
        for mount, info in data.items():
            if isinstance(info, dict) and info.get("type") == "kv":
                mounts.append(mount)
        return mounts
    except Exception as e:
        print(f"❌ Cannot get mounts: {e}")
        return []


def export_to_csv():
    mounts = get_kv_mounts()
    with open("vault_secrets.csv", "w", newline="") as csvfile:
        fieldnames = ["Mount Path", "Secret Path", "KV Version"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for mount in mounts:
            try:
                is_v2 = is_kv_v2(mount)
                print(f"🔍 Scanning {mount} ({'v2' if is_v2 else 'v1'}) in namespace {VAULT_NAMESPACE or '[root]'}")
                secrets = list_secrets_recursively(mount, is_v2=is_v2)
                for secret_path in secrets:
                    writer.writerow({
                        "Mount Path": mount,
                        "Secret Path": secret_path,
                        "KV Version": "v2" if is_v2 else "v1"
                    })
            except Exception as e:
                print(f"⚠️ Error with mount {mount}: {e}")


if __name__ == "__main__":
    export_to_csv()
