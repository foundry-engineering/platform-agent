"""Trace only the pinned engine's stderr to a private diagnostic file."""
from __future__ import annotations

import os
import subprocess
from typing import Any, cast
from unittest.mock import patch

from engineering_agent import model_host


def main() -> int:
    descriptor = os.open(os.environ['FOUNDRY_PRIVATE_ENGINE_LOG'],
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    original = subprocess.Popen
    with os.fdopen(descriptor, 'wb') as log:
        def traced(arguments: Any, *args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            if (isinstance(arguments, list) and arguments
                    and str(arguments[0]).endswith('/llama-server')):
                kwargs['stderr'] = log
            return cast(subprocess.Popen[bytes], original(arguments, *args, **kwargs))

        with patch.object(subprocess, 'Popen', traced):
            return model_host.main()


if __name__ == '__main__':
    raise SystemExit(main())
