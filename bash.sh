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

# For kv-v1, we use vault read directly on the path
dump_kv_v1_secret_keys() {
    local engine=$1
    local path=$2
    full_path="${engine}${path}"
    keys=$(vault read -format=json "$full_path" 2>/dev/null | jq -r '.data | keys[]' 2>/dev/null)

    for k in $keys; do
        echo "kv-v1,$engine,/$path,$k" >> "$OUTPUT_FILE"
    done
}

# For kv-v2, we use vault kv get on data/ path
dump_kv_v2_secret_keys() {
    local engine=$1
    local path=$2
    full_path="${engine}data/${path}"
    keys=$(vault read -format=json "$full_path" 2>/dev/null | jq -r '.data.data | keys[]' 2>/dev/null)

    for k in $keys; do
        echo "kv-v2,$engine,/$path,$k" >> "$OUTPUT_FILE"
    done
}

# Recursive traversal for kv-v1
traverse_kv_v1() {
    local engine=$1
    local path=$2

    children=$(vault list -format=json "${engine}${path}" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        return
    fi

    for item in $(echo "$children" | jq -r '.[]'); do
        if [[ "$item" == */ ]]; then
            traverse_kv_v1 "$engine" "${path}${item}"
        else
            dump_kv_v1_secret_keys "$engine" "${path}${item}"
        fi
    done
}

# Recursive traversal for kv-v2
traverse_kv_v2() {
    local engine=$1
    local path=$2

    children=$(vault list -format=json "${engine}metadata/${path}" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        return
    fi

    for item in $(echo "$children" | jq -r '.[]'); do
        if [[ "$item" == */ ]]; then
            traverse_kv_v2 "$engine" "${path}${item}"
        else
            dump_kv_v2_secret_keys "$engine" "${path}${item}"
        fi
    done
}

# MAIN
vault secrets list -format=json | jq -r 'keys[]' | while read -r mount; do
    engine=$(echo "$mount" | sed 's:/$::')
    type=$(vault secrets list -format=json | jq -r ".[\"${mount}\"].type")

    if [[ "$type" == "kv" ]]; then
        version=$(detect_kv_version "$engine/")
        if [[ "$version" == "kv-v2" ]]; then
            traverse_kv_v2 "$engine/" ""
        else
            traverse_kv_v1 "$engine/" ""
        fi
    fi
done

echo "✅ Finished! Output in: $OUTPUT_FILE"
