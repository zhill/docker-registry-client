from __future__ import absolute_import

import time
import logging
import docker_registry_client._BaseClient
from requests import get


logging.basicConfig(level='DEBUG')
logger = logging.getLogger(__name__)

class TestAuthCommonBaseClient(object):
    """
    Runs tests of the auth handling against DockerHub. Requires network connectivity but no DockerHub credentials
    """
    host = 'https://index.docker.io'
    version_check_url = '/v2/'
    nginx_url = '/v2/library/nginx/tags/list'
    nginx_latest_manifest = '/v2/library/nginx/manifests/latest'

    def test_check_status(self):
        print 'Listing the catalog'
        response = docker_registry_client._BaseClient.AuthCommonBaseClient(self.host)._http_call(self.version_check_url, method=get)
        print 'Got response: %s' % str(response)

    def test_tag_listing(self):
        response = docker_registry_client._BaseClient.AuthCommonBaseClient(self.host)._http_call(self.nginx_url,
                                                                                     method=get)
        print 'Got response: %s' % str(response)
        if hasattr(response, 'content'):
            print 'Content: ' + str(response.content)

    def test_token_timeout(self):
        client = docker_registry_client._BaseClient.AuthCommonBaseClient(self.host)
        try:

            for i in range(0, 5):
                response =client._http_call(self.nginx_latest_manifest, method=get)
                print str(response)
                response = None
                print 'Sleeping for 5 minutes to try again'
                time.sleep(5*60)
        except Exception as e:
            logger.error('Exception: ' + e.message, exc_info=1)

    def test_token_invalidate(self):
        t = docker_registry_client._BaseClient.OAuth2TokenHandler()
        t._add_token('http://testurl', {'param':'value'}, {'token':'abc'})
        t.invalidate_token('abc')

if __name__ == '__main__':
    t = TestAuthCommonBaseClient()
    print 'Checking status'
    t.test_check_status()
    print 'Listing nginx tags'
    t.test_tag_listing()
    print 'Testing token invalidation'
    t.test_token_invalidate()
    print 'Testing timeout'
    t.test_token_timeout()



