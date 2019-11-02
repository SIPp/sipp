#!/bin/bash

for file in $(find . -name '*.xml')
do
  if ! xmllint --dtdvalid ./sipp.dtd $file
  then
    echo "ERROR: $file failed validation"
    exit 1
  fi
done

echo "All files OK"
