
import sys
import os

# Ensure current directory is in path to mimic pipeline behavior
sys.path.append(os.getcwd())

try:
    import tools.lachesis.renderer
    print(f"RENDERER PATH: {tools.lachesis.renderer.__file__}")
except Exception as e:
    print(f"RENDERER IMPORT FAILED: {e}")

try:
    import tools.lachesis.analyzer
    print(f"ANALYZER PATH: {tools.lachesis.analyzer.__file__}")
except Exception as e:
    print(f"ANALYZER IMPORT FAILED: {e}")
