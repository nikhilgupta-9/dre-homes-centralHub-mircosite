#!/bin/bash
# Double-click to start SpamGuard Studio in your browser.
cd "$(dirname "$0")" || exit 1
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js install nahi hai. https://nodejs.org se 'LTS' download karke install karo, phir ye file dobara kholo."
  open "https://nodejs.org" 2>/dev/null
  read -n 1 -s -r -p "Koi key dabao..."; exit 1
fi
if [ ! -d node_modules ]; then
  echo "Pehli baar setup ho raha hai (1-2 minute)..."
  npm install --omit=dev --ignore-scripts --no-audit --no-fund || { read -n 1 -s -r -p "Setup fail hua. Internet check karo."; exit 1; }
fi
node bin/sg-web.js
