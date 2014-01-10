# -*- coding: utf-8 -*-
'''
    simpleoauth.compat
    ------------------

    A module providing tools for cross-version compatibility.
'''

import sys

if sys.version_info < (3, 0):  # pragma: no cover
    from urllib import quote_plus, urlencode
    from urlparse import parse_qsl, urlsplit, urlunsplit

    def is_basestring(s):
        return isinstance(s, basestring)  # NOQA

else:  # pragma: no cover
    from urllib.parse import (parse_qsl, quote_plus, urlencode, urlsplit,
                              urlunsplit)

    # placate pyflakes
    (quote_plus, parse_qsl, urlencode, urlsplit, urlunsplit)

    def is_basestring(s):
        return isinstance(s, (str, bytes))
