#!/bin/bash
# Double-click: SpamGuard Studio browser me khulega.
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 nahi mila. python.org/downloads se install karo, phir dobara kholo."
  open "https://www.python.org/downloads/" 2>/dev/null
  read -n 1 -s -r -p "Koi key dabao..."; exit 1
fi
python3 studio.py
