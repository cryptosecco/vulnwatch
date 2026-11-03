"""Entry point. Run with: /usr/bin/python3 -I -B vulnwatch.py <comando>"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from vulnwatch import cli  # noqa: E402

raise SystemExit(cli.main(sys.argv[1:]))
