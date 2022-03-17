#!/bin/sh

failures=0
for file in $(find . -name '*.xml'); do
    if ! xmllint --path . --dtdvalid ./sipp.dtd $file >/dev/null; then
        echo "ERROR: $file failed validation"
        failures=$((failures+1))
    fi
done

if test $failures -ne 0; then
    echo "Not OK" >&2
    exit 1
fi

echo "All files OK" >&2
