"""Subprocess runner: argv lists only, never a shell, always a timeout, never raises."""
import subprocess
from typing import Dict, List, Optional, Tuple


class Runner:
    def __call__(self, argv: List[str], timeout: float, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, env=env, check=False)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(list(argv), 124, "", "timeout")
        except OSError as e:
            return subprocess.CompletedProcess(list(argv), 127, "", str(e))


class FakeRunner:
    def __init__(self, responses: Dict[Tuple[str, ...], subprocess.CompletedProcess]):
        self.responses = dict(responses)
        self.calls: List[Tuple[List[str], Optional[Dict[str, str]]]] = []

    def __call__(self, argv: List[str], timeout: float, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        self.calls.append((list(argv), None if env is None else dict(env)))
        r = self.responses.get(tuple(argv))
        if r is None:
            return subprocess.CompletedProcess(list(argv), 127, "", "")
        return r
