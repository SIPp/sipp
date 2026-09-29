#!/bin/sh

failures=0
# The XML files of SIPp, not those of the submodules.
for file in $(find . \( -path ./third_party -o -path ./gtest \) -prune -o -name '*.xml' -print); do
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
