# -*- coding: utf-8 -*-
'''
    simpleoauth.oauth2
    ------------------

    OAuth 2.0 signing logic.
'''


def sign(access_token, bearer_auth=False, key_name='access_token'):
    '''
    Signs a request.

    Given the relative simplicity of OAuth 2.0 juxtapose 1.0, this function
    takes an access token and returns it either in the form of a dictionary,
    whereby the key is the parameter key and the value the access token or if
    bear authentication is indicated, returns the authorization header as
    a string.

    :param access_token: The access token.
    :type access_token: str
    :param bearer_auth: Header authentication using bearer tokens, defauls to
        ``False``.
    :type bearer_auth: bool
    :param key_name: The key with which the access token is recognized as
        a parameter.
    :type key_name: str
    '''
    if bearer_auth:
        return {'Authorization': 'Bearer {token}'.format(token=access_token)}
    return {key_name: access_token}
