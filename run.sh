#!/usr/bin/env sh
# One command. Scenarios, then independent replay, then tests, then screenshot.
set -e
[ -d node_modules ] || npm install
npm run verify
