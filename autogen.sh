#!/bin/sh
set -e

autoreconf -vifs

# Optional: for git checkout only. Adds prerequisites for testing framework.
if which git >/dev/null && test -d .git; then
	git submodule update --init
fi
