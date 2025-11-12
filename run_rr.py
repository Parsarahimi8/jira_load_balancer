#!/usr/bin/env python3
import os, sys, pathlib
try:
    from dotenv import load_dotenv
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-dotenv"])
    from dotenv import load_dotenv

# NEW: chdir to this file's directory so relative paths go next to the scripts
BASE_DIR = pathlib.Path(__file__).resolve().parent
os.chdir(BASE_DIR)

load_dotenv(dotenv_path=".env", override=True)
os.execvpe(sys.executable, [sys.executable, "round_robin_jira.py"], os.environ)
