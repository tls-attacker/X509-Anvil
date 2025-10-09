# 1. Get IDs from all tests
grep -rhoP '@AnvilTest\([^)]*id\s*=\s*"\K[^"]+' src/ \
  | grep -E '^(basic|extension)-[0-9a-f]{10}$' \
  | sort -u > ids.txt


# 2. Get keys from json
jq -r 'keys[]' ./src/main/resources/metadata.json | sort -u > meta.txt

# 3. Calculate differences
comm -23 ids.txt meta.txt > ids_without_meta.txt

# 4. Print and count
cat ids_without_meta.txt
count=$(wc -l < ids_without_meta.txt)

echo ""
echo "👉 Es fehlen noch $count Metadaten-Einträge für deine Tests."
