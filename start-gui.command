#!/bin/zsh
cd "${0:A:h}" || exit 1
exec .venv/bin/python grok_register_ttk.py
