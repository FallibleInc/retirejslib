import logging
from .retirejs import (scan_endpoint,
					   scan_file_content,
					   scan_filename,
					   scan_uri,
					   is_vulnerable)

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

