"""Stop the PDS and SEEM experiments that bootlooped this phone."""

from __future__ import annotations

import os


def require_pds_write() -> None:
    if os.environ.get('V3XX_ALLOW_PDS_WRITE') != '1':
        raise SystemExit(
            'PDS and SEEM writes bootlooped this phone. '
            'See docs/what-did-not-work.md. '
            'Set V3XX_ALLOW_PDS_WRITE=1 to run this anyway.'
        )
