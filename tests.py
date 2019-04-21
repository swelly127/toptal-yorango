import os
import yorango
import unittest
import tempfile

class YorangoTestCase(unittest.TestCase):

    def setUp(self):
        yorango.app.config['DEBUG'] = tempfile.mkstemp()
        self.app = yorango.app.test_client()

    def tearDown(self):
        pass

    def test_index(self):
        rv = self.app.get('/')
        assert '<h2>Login</h2>' in rv.data

if __name__ == '__main__':
    unittest.main()