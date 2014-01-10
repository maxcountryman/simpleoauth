# -*- coding: utf-8 -*-
'''
    simpleoauth.utils
    -----------------

    SimpleOAuth utilities.
'''

from simpleoauth.compat import is_basestring, quote_plus

FORM_URLENCODED = 'application/x-www-form-urlencoded'
OPTIONAL_OAUTH_PARAMS = ('oauth_callback', 'oauth_verifier', 'oauth_version')


def ensure_encoding(s):
    '''
    Ensures a given string is properly encoded.

    :param s: A string to check.
    :type s: str or unicode
    '''
    if is_basestring(s) and not isinstance(s, bytes):
        return s.encode('utf-8')
    return s


def sorted_urlencode_utf8(params):
    def kv(k, v):
        kv_fmt = '{k}={v}'
        k, v = ensure_encoding(k), ensure_encoding(v)
        if is_basestring(k):
            k = quote_plus(k)
        if is_basestring(v):
            v = quote_plus(v)
        return kv_fmt.format(k=k, v=v)

    if hasattr(params, 'items'):
        params = params.items()

    sorted_params = []
    for k, v in sorted(params):
        sorted_params.append(kv(k, v))

    return '&'.join(sorted_params)
