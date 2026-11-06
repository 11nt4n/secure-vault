# Backward-compatible test entry point retained for existing operator scripts.
import runpy
from pathlib import Path
base = Path(__file__).resolve().parent
runpy.run_path(str(base / 'iteration5_relational_static_test.py'), run_name='__main__')
