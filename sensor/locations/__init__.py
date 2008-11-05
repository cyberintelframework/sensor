
import logging
import platform

system = platform.system()

# import system specific locations
if system == 'Linux':
    from linux import *
elif system == 'OpenBSD':
    from openbsd import *
else:
    logging.error("unsupported system: " + system)
    import sys
    sys.exit(1)

