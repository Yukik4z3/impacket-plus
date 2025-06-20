# Set default logging handler to avoid "No handler found" warnings.
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

# All modules inside this library MUST use this logger (impacket)
# It is up to the library consumer to do whatever is wanted 
# with the logger output. By default it is forwarded to the 
# upstream logger

__version__ = "0.2.0"

LOG = logging.getLogger(__name__)
LOG.addHandler(NullHandler())