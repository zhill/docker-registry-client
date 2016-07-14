from __future__ import absolute_import

import docker_registry_client._BaseClient
from requests import get


class TestAuthCommonBaseClient(object):
    """
    Runs tests of the auth handling against DockerHub. Requires network connectivity but no DockerHub credentials
    """
    host = 'https://index.docker.io'
    version_check_url = '/v2/'
    nginx_url = '/v2/library/nginx/tags/list'

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


if __name__ == '__main__':
    t = TestAuthCommonBaseClient()
    print 'Checking status'
    t.test_check_status()
    print 'Listing nginx tags'
    t.test_tag_listing()

