"""SpamGuard Studio scanner: pure-Python (stdlib only) port of the Node scanner.

    from sgstudio.scanner import scan_site, render_text
    report = scan_site('/path/to/site-or.zip')
    print(render_text(report))

The scanner only reads files; it never runs any code from the site.
"""
from . import bulk, util  # noqa: F401
from .bulk import scan_many, write_bulk_outputs  # noqa: F401
from .index import VERSION, scan_site  # noqa: F401
from .loader import extract_zip, find_site_root, prepare_input  # noqa: F401
from .report import KIND, REASON, render_bulk_text, render_text  # noqa: F401
from .util import SKIP_DIRS, SKIP_FILE, ScanError  # noqa: F401
