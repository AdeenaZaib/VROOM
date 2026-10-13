"""Let the tests find the pipeline scripts and the dataset, wherever they
live in the repo. Nothing here needs editing if folders move later.
"""
import sys
from pathlib import Path
 
ROOT = Path(__file__).parent
 
# Find the folder holding extract_features.py and put it on the import path.
for candidate in ROOT.rglob("extract_features.py"):
    sys.path.insert(0, str(candidate.parent))
    break
else:
    raise RuntimeError("extract_features.py not found anywhere under the repo")
 
# Same for features.csv, so the dataset tests can run instead of skipping.
for csv in ROOT.rglob("features.csv"):
    import os
    os.environ.setdefault("CARAZONE_FEATURES", str(csv))
    break
 