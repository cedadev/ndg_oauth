from ndgoauthclient.tests import *

class TestClientController(TestController):

    def test_index(self):
        response = self.app.get(url(controller='client', action='index'))
        # Test response...
