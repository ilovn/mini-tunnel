#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'runtime'))
from harnesskit.cli import main
raise SystemExit(main(['--project', str(Path(__file__).resolve().parent.parent), *sys.argv[1:]]))
