OUTPUT="dataset.cc"
INPUT="candidates.csv"
#redo-ifchange "$INPUT"

cat <<eof > "$OUTPUT"
#include <string>
#include <vector>
#include "trigram_minsketch.h"

std::vector<TrigramSet> trigram = {
eof

tail -n +2 "$INPUT" | while read -r protocol tgs np nc tf; do
    echo "  {${protocol},"0x$(echo "$tgs" | sed "s/^['\"]//;s/['\"]$//")" }," >> "$OUTPUT"
done

echo "};" >> "$OUTPUT"