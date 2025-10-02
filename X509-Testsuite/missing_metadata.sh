# 1. IDs aus den Java-Dateien holen
grep -rhoP '@AnvilTest\([^)]*id\s*=\s*"\K[^"]+' src/ \
  | grep -E '^(basic|extension)-[0-9a-f]{10}$' \
  | sort -u > ids.txt


# 2. Keys aus metadata.json holen
jq -r 'keys[]' ./src/main/resources/metadata.json | sort -u > meta.txt

# 3. Differenz berechnen (IDs ohne Metadaten)
comm -23 ids.txt meta.txt > ids_without_meta.txt

# 4. Ausgabe + Anzahl
cat ids_without_meta.txt
count=$(wc -l < ids_without_meta.txt)

echo ""
echo "👉 Es fehlen noch $count Metadaten-Einträge für deine Tests."
