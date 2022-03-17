#!/bin/sh

print_listing=true
err=0
TAB=`printf '\t'`

while getopts ':l' opt
do
case $opt in
l) print_listing=false;;
esac
done

list_sed='s/^/    /;s/:/: ^/'

files_with_tabs=$(
    find include src '!' -name config.h \
      '(' -name '*.cpp' -o -name '*.hpp' -o -name '*.c' -o -name '*.h' ')' |
    xargs grep -l "$TAB")
if test -n "$files_with_tabs"; then
    echo "tabs encountered in one or more source files:" >&2
    for file in $files_with_tabs; do
        echo "  $file" >&2
        if $print_listing; then
            grep -n "$TAB" $file | sed -e "$list_sed" | cat -A >&2
        fi
    done
    echo >&2
    err=$((err+1))
fi

files_with_trailing_ws=$(
    find include src '!' -name config.h \
      '(' -name '*.cpp' -o -name '*.hpp' -o -name '*.c' -o -name '*.h' ')' |
    xargs grep -l '[[:blank:][:cntrl:]]$')
if test -n "$files_with_trailing_ws"; then
    echo "trailing whitespace found in one or more source files:" >&2
    for file in $files_with_trailing_ws; do
        echo "  $files_with_trailing_ws" >&2
        if $print_listing; then
            grep -n '[[:blank:][:cntrl:]]$' $file |
                sed -e "$list_sed" | cat -A >&2
        fi
    done
    echo >&2
    err=$((err+1))
fi

files_with_not_4_spaces=$(
    find include src '!' -name config.h \
      '(' -name '*.cpp' -o -name '*.hpp' -o -name '*.c' -o -name '*.h' ')' |
    xargs grep -lE '^(  \}| {1,3}[a-z_])')
if test -n "$files_with_not_4_spaces"; then
    echo "files with non-standard indentation found:" >&2
    for file in $files_with_not_4_spaces; do
        echo "  $file" >&2
        if $print_listing; then
            grep -nE '^(  \}| {1,3}[a-z_])' $file |
                sed -e "$list_sed" | cat -A >&2
        fi
    done
    echo >&2
    err=$((err+1))
fi

exit $err
