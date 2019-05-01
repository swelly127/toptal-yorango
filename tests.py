import os
import tempfile
import unittest

from models import *
import yorango

class YorangoTestCase(unittest.TestCase):

	def setUp(self):
	    yorango.app.config['DEBUG'] = tempfile.mkstemp()
	    self.app = yorango.app.test_client()

	def tearDown(self):
	    pass

	def test_index_for_admin(self):
		with self.app as client:
			with client.session_transaction() as session:
				session['user'] = { "role": int(Role.ADMIN) }
		index = self.app.get('/')
		assert 'See listings' in index.data
		assert 'Create a new listing' in index.data
		assert 'View all users' in index.data

	def test_index_for_realtor(self):
		with self.app as client:
			with client.session_transaction() as session:
				session['user'] = { "role": int(Role.REALTOR) }
		index = self.app.get('/')
		assert 'See listings' in index.data
		assert 'Create a new listing' in index.data
		assert 'View all users' not in index.data

	def test_index_for_tenant(self):
		with self.app as client:
			with client.session_transaction() as session:
				session['user'] = { "role": int(Role.TENANT) }
		index = self.app.get('/')
		assert 'See listings' in index.data
		assert 'Create a new listing' not in index.data
		assert 'View all users' not in index.data

if __name__ == '__main__':
    unittest.main()