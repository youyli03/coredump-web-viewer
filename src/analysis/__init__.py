"""Processing logic: everything that is not HTTP.

`web/` may import from here; nothing here may import from `web/`, because the analysis layer must not
know that HTTP exists.
"""

from __future__ import annotations
