#!/bin/bash

OUTPUT_FILE="vault_keys.csv"
echo "engine_type,engine,path,key" > "$OUTPUT_FILE"

# Detect kv version (1 or 2)
detect_kv_version() {
    local mount=$1
    local config_path="${mount}config"

    version=$(vault read -format=json "$config_path" 2>/dev/null | jq -r '.data.options.version' 2>/dev/null)

    if [[ "$version" == "2" ]]; then
        echo "kv-v2"
    else
        echo "kv-v1"
    fi
}

# Recursive traversal for kv-v1
list_kv_v1() {
    local engine=$1
    local path=$2

    keys=$(vault list -format=json "${engine}${path}" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        return
    fi

    for key in $(echo "$keys" | jq -r '.[]'); do
        if [[ "$key" == */ ]]; then
            list_kv_v1 "$engine" "${path}${key}"
        else
            echo "kv-v1,$engine,$path,$key" >> "$OUTPUT_FILE"
        fi
    done
}

# Recursive traversal for kv-v2 (metadata list)
list_kv_v2() {
    local engine=$1
    local path=$2

    keys=$(vault list -format=json "${engine}metadata/${path}" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        return
    fi

    for key in $(echo "$keys" | jq -r '.[]'); do
        if [[ "$key" == */ ]]; then
            list_kv_v2 "$engine" "${path}${key}"
        else
            echo "kv-v2,$engine,/${path},$key" >> "$OUTPUT_FILE"
        fi
    done
}

# MAIN: iterate over all secret mounts
vault secrets list -format=json | jq -r 'keys[]' | while read -r mount; do
    engine=$(echo "$mount" | sed 's:/$::')  # e.g., "secret"
    type=$(vault secrets list -format=json | jq -r ".[\"${mount}\"].type")

    if [[ "$type" == "kv" ]]; then
        version=$(detect_kv_version "$engine/")
        if [[ "$version" == "kv-v2" ]]; then
            list_kv_v2 "$engine/" ""
        else
            list_kv_v1 "$engine/" ""
        fi
    fi
done

echo "✅ Done! Output written to $OUTPUT_FILE"
