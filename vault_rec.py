import hvac
import csv

def list_all_secrets(client, mount_point, path='', kv_version=2):
    secrets = []
    try:
        if kv_version == 2:
            result = client.secrets.kv.v2.list_secrets(
                mount_point=mount_point,
                path=path
            )
        else:
            result = client.secrets.kv.v1.list_secrets(
                mount_point=mount_point,
                path=path
            )

        for key in result['data']['keys']:
            full_path = f"{path}{key}"
            if key.endswith('/'):
                secrets.extend(list_all_secrets(client, mount_point, full_path, kv_version))
            else:
                secrets.append(full_path)
    except hvac.exceptions.InvalidPath:
        pass
    return secrets

def detect_kv_version(client, mount_point):
    try:
        mount_config = client.sys.read_mount_configuration(mount_point=mount_point)
        version = mount_config['data']['options'].get('version', '1')
        return int(version)
    except Exception:
        return 1

def main():
    VAULT_ADDR = 'http://localhost:8200'
    VAULT_TOKEN = 'your-root-or-client-token'
    NAMESPACE = 'your-namespace'  # Use "" for default/root namespace
    SECRET_ENGINE = 'secret'      # Your KV mount point
    OUTPUT_FILE = 'vault_secrets.csv'

    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    client.adapter.session.headers.update({'X-Vault-Namespace': NAMESPACE})

    kv_version = detect_kv_version(client, SECRET_ENGINE)
    print(f"Detected KV version: {kv_version}")

    secrets = list_all_secrets(client, mount_point=SECRET_ENGINE, kv_version=kv_version)

    print(f"Found {len(secrets)} secrets. Writing to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Secret Path'])  # Header
        for secret in secrets:
            writer.writerow([secret])

    print("✅ Done writing CSV.")

if __name__ == '__main__':
    main()
