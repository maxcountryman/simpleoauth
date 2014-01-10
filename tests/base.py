import unittest

if not hasattr(unittest.TestCase, 'assertIsNotNone'):
    try:
        import unittest2 as unittest
    except ImportError:
        raise Exception('unittest2 is required to run the test suite')


class SimpleOauthTestCase(unittest.TestCase):
    def setUp(self):
        pass
