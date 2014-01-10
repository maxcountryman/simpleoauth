# -*- coding: utf-8 -*-
'''
    simpleoauth.oauth1
    ------------------

    OAuth 1.0 and 1.0a signing logic.
'''


import base64
import hmac

from copy import deepcopy
from hashlib import sha1
from random import random
from time import time

from simpleoauth.compat import (is_basestring, quote_plus, parse_qsl, urlsplit,
                                urlunsplit)
from simpleoauth.utils import (FORM_URLENCODED, ensure_encoding,
                               OPTIONAL_OAUTH_PARAMS, sorted_urlencode_utf8)


class OAuth1Error(Exception):
    pass


def _escape(s):
    '''
    Escapes a string, ensuring it is encoded as a UTF-8 octet.

    :param s: A string to be escaped and encoded.
    :type s: str
    '''
    return quote_plus(ensure_encoding(s), safe='~')


def _remove_qs(url):
    '''
    Removes a query string from a URL before signing.

    :param url: The URL to strip.
    :type url: str
    '''
    scheme, netloc, path, query, fragment = urlsplit(url)
    return urlunsplit((scheme, netloc, path, '', fragment))


def _params_and_data(req_kwargs):
    params = req_kwargs.get('params', {})
    if is_basestring(params):
        params = dict(parse_qsl(params))

    data = req_kwargs.get('data', {})
    if is_basestring(data):
        data = dict(parse_qsl(data))

    return params, data


def _normalize_params(oauth_params, req_kwargs):
    '''
    This process normalizes the request parameters as detailed in the OAuth
    1.0 spec.

    Additionally we apply a `Content-Type` header to the request of the
    `FORM_URLENCODE` type if the `Content-Type` was previously set, i.e. if
    this is a `POST` or `PUT` request. This ensures the correct header is
    set as per spec.

    Finally we sort the parameters in preparation for signing and return
    a URL encoded string of all normalized parameters.

    :param oauth_params: OAuth params to sign with.
    :type oauth_params: dict
    :param req_kwargs: Request kwargs to normalize.
    :type req_kwargs: dict
    '''
    params, data = _params_and_data(req_kwargs)

    headers = req_kwargs.get('headers', {})
    has_content_type = 'Content-Type' in headers
    if has_content_type and headers['Content-Type'] == FORM_URLENCODED:
        # NOTE: gratuitous casting here, due to Python 3 oddities
        normalized = dict(list(params.items()) +
                          list(data.items()) +
                          list(oauth_params.items()))
    else:
        normalized = dict(list(params.items()) + list(oauth_params.items()))

    return sorted_urlencode_utf8(normalized).replace('+', '%20')


def hmac_sha1_signer(consumer_secret,
                     access_token_secret,
                     method,
                     url,
                     oauth_params,
                     req_kwargs):
    '''
    Given a set of request params, signs them using the HMAC-SHA1 signature
    method. Returns the signature.

    :param consumer_secret: Consumer secret.
    :type consumer_secret: str
    :param access_token_secret: Access token secret.
    :type access_token_secret: str
    :param method: The method of this particular request.
    :type method: str
    :param url: The URL of this particular request.
    :type url: str
    :param oauth_params: OAuth parameters.
    :type oauth_params: dict
    :param req_kwargs: Keyworded args that will be sent to the request
        method.
    :type req_kwargs: dict
    '''
    url = _remove_qs(url)

    oauth_params = _normalize_params(oauth_params, req_kwargs)
    parameters = map(_escape, [method, url, oauth_params])

    key = _escape(consumer_secret) + '&'
    if access_token_secret is not None:
        key += _escape(access_token_secret)

    # build a Signature Base String
    signature_base_string = '&'.join(parameters)

    # hash the string with HMAC-SHA1
    hashed = hmac.new(key.encode('utf-8'),
                      signature_base_string.encode('utf-8'),
                      sha1)

    # return the signature
    return base64.b64encode(hashed.digest()).decode('utf-8')


def rsa_sha1_signer(consumer_secret,
                    access_token_secret,
                    method,
                    url,
                    oauth_params,
                    req_kwargs):  # pragma: no cover
    raise NotImplementedError


def plaintext_signer(consumer_secret,
                     access_token_secret,
                     method,
                     url,
                     oauth_params,
                     req_kwargs):  # pragma: no cover
    raise NotImplementedError


signature_names = {hmac_sha1_signer.__name__: 'HMAC-SHA1',
                   rsa_sha1_signer.__name__: 'RSA-SHA1',
                   plaintext_signer.__name__: 'PLAINTEXT'}


def _parse_optional_params(oauth_params, req_kwargs):
    '''
    Parses and sets optional OAuth 1.0/a parameters on a request.

    :param oauth_params: The OAuth parameters to parse.
    :type oauth_params: str
    :param req_kwargs: The keyworded arguments passed to the request
        method.
    :type req_kwargs: dict
    '''
    params, data = _params_and_data(req_kwargs)

    for oauth_param in OPTIONAL_OAUTH_PARAMS:
        if oauth_param in params:
            oauth_params[oauth_param] = params.pop(oauth_param)

        if oauth_param in data:
            oauth_params[oauth_param] = data.pop(oauth_param)

        if params:
            req_kwargs['params'] = params

        if data:
            req_kwargs['data'] = data


def make_params(req_kwargs,
                consumer_key,
                signature_name,
                access_token=None,
                version='1.0'):
    '''
    Given a dictionary, `req_kwargs`, returns a dictionary of OAuth 1.0/a
    signing parameters.

    :param req_kwargs: A request dictionary formatted such that a keyword
        `params` and a keyword `data` represent the request parameters and
        request body, respectively.
    :type request: dict
    '''
    oauth_params = {}

    oauth_params['oauth_consumer_key'] = consumer_key
    oauth_params['oauth_nonce'] = \
        sha1(str(random()).encode('utf-8')).hexdigest()
    oauth_params['oauth_signature_method'] = signature_name
    oauth_params['oauth_timestamp'] = int(time())

    if access_token is not None:
        oauth_params['oauth_token'] = access_token

    oauth_params['oauth_version'] = version

    _parse_optional_params(oauth_params, req_kwargs)

    return oauth_params


def make_auth_header(oauth_params, realm=None):
    '''
    Given a dictionary, `oauth_params`, constructs a header string suitable
    for header-based authentication. Returns the auth header string.

    :param oauth_params: A dictionary of OAuth 1.0/a parameters.
    :type oauth_params: dict
    :param realm: Authentication realm, defaults to `None`.
    :type realm: str
    '''
    auth_header = 'OAuth realm="{realm}"'.format(realm=realm or '')
    params = ''

    for k, v in sorted(oauth_params.items()):
        params += ',{key}="{value}"'.format(key=k, value=quote_plus(str(v)))

    auth_header += params
    return auth_header


def sign(req_kwargs,
         url,
         method,
         consumer_key,
         consumer_secret,
         access_token=None,
         access_token_secret=None,
         header_auth=False,
         realm=None,
         signer=hmac_sha1_signer):
    '''
    Signs a request.

    Expects a dictionary of request arguments, the request URL, the request
    method, consumer key, and consumer secret. Optionally, access token and
    acess token secret may be provided. A realm may be specified. And an
    arbitrary signer function may be passed in.

    The request dictionary may contain `data`, and `params` keys, others will
    be ignored. These keys should hold dictionaries or strings as values.

    For example:

        req_kwargs = {'data': 'foo=bar&baz=qux'}
        url = 'http://example.com/'
        method = 'POST'
        consumer_key = 'foo'
        consumer_secret = 'bar'

        oauth_params = sign(req_kwargs,
                            url,
                            method,
                            consumer_key,
                            consumer_secret)

    If header authentication is specified, a string representation of the
    header is returned. Otherwise a dictionary of signed OAuth parameters is
    returned. This dictionary will contain the necessary OAuth parameters for
    authenticating with the resource.

    These may either be used with a client or a provider. In the
    former case, a client would send the sorted dictionary back to the
    provider. In the latter case a provider would sign incoming requests and
    ensure the signatures match.

    :param req_kwargs: A request dictionary formatted such that a keyword
        `params` and a keyword `data` represent the request parameters and
        request body, respectively.
    :type req_kwargs: dict
    :param url: The URL to sign against.
    :type url: str
    :param method: The request method, e.g. "GET".
    :type method: str
    :param consumer_key: The consumer key.
    :type consumer_key: str
    :param consumer_secret: The consumer secret:
    :type consumer_secret: str
    :param access_token: The access token, defaults to ``None``.
    :type access_token: str
    :param access_token_secret: The access token secret, defaults to ``None``.
    :type access_token_secret: str
    :param header_auth: Whether or not the header should be used for
        authentication, defaults to ``False``.
    :type header_auth: bool
    :param realm: The realm, defaults to ``None``.
    :type realm: str
    :param signer: The signing method, defaults to `hmac_sha1_signer`.
    :type signer: function
    '''
    req_kwargs = deepcopy(req_kwargs)

    if signer.__name__ not in signature_names:
        raise OAuth1Error('Signer must be named as one of: '
                          '"hmac_sha1_signer", '
                          '"rsa_sha1_signer", '
                          '"plaintext_signer"')

    signature_name = signature_names[signer.__name__]

    oauth_params = make_params(req_kwargs,
                               consumer_key,
                               signature_name,
                               access_token)

    oauth_params['oauth_signature'] = signer(consumer_secret,
                                             access_token_secret,
                                             method,
                                             url,
                                             oauth_params,
                                             req_kwargs)

    if header_auth:
        auth = {'Authorization': make_auth_header(oauth_params, realm)}
        req_kwargs.setdefault('headers', {})
        req_kwargs['headers'].update(auth)
        return req_kwargs

    headers = req_kwargs.get('headers', {})
    has_content_type = 'content-type' in headers

    # TODO: Probably should check HTTP Method here, on the other hand,
    # non-entity methods should NOT be using `FORM_URLENCODED`.
    if has_content_type and headers['content-type'] == FORM_URLENCODED:
        req_kwargs.setdefault('data', {})
        req_kwargs['data'].update(oauth_params)
    else:
        req_kwargs.setdefault('params', {})
        req_kwargs['params'].update(oauth_params)

    return req_kwargs
