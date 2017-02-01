from __future__ import absolute_import

from .Image import Image


class BaseRepository(object):
    def __init__(self, client, repository, namespace=None):
        self._client = client
        self.repository = repository
        self.namespace = namespace

    @property
    def name(self):
        if self.namespace:
            return "{namespace}/{repository}".format(namespace=self.namespace,
                                                     repository=self.repository)
        return self.repository


class RepositoryV1(BaseRepository):
    def __init__(self, client, repository, namespace=None):
        if namespace is None:
            namespace = 'library'

        super(RepositoryV1, self).__init__(client, repository,
                                           namespace=namespace)
        self._images = None

    def __repr__(self):
        return 'RepositoryV1({name})'.format(name=self.name)

    def refresh(self):
        self._images = self._client.get_repository_tags(self.namespace,
                                                        self.repository)

    def tags(self):
        if self._images is None:
            self.refresh()

        return list(self._images.keys())

    def data(self, tag):
        return self._client.get_tag_json(self.namespace, self.repository, tag)

    def image(self, tag):
        if self._images is None:
            self.refresh()

        image_id = self._images[tag]
        return Image(image_id, self._client)

    def untag(self, tag):
        return self._client.delete_repository_tag(self.namespace,
                                                  self.repository, tag)

    def tag(self, tag, image_id):
        return self._client.set_tag(self.namespace, self.repository,
                                    tag, image_id)

    def delete_repository(self):
        # self._client.delete_repository(self.namespace, self.repository)
        raise NotImplementedError()


class RepositoryV2(BaseRepository):
    def __init__(self, client, repository, namespace=None):
        super(RepositoryV2, self).__init__(client, repository,
                                           namespace=namespace)
        self._tags = None

    def __repr__(self):
        return 'RepositoryV2({name})'.format(name=self.name)

    def tags(self):
        if self._tags is None:
            self.refresh()

        return self._tags

    def manifest(self, tag):
        """
        Return a tuple, (manifest, digest), for a given tag
        """
        return self._client.get_manifest_and_digest(self.name, tag)

    def delete_manifest(self, digest):
        return self._client.delete_manifest(self.name, digest)

    def refresh(self):
        response = self._client.get_repository_tags(self.name)
        self._tags = response['tags']

    def get_manifest_digest(self, tag):
        return self._client.get_manifest_digest(self.name, tag)

    def get_blob(self, digest):
        return self._client.get_blob(self.name, digest)

    def layer_meta(self, layer_entry):

        if 'size' in layer_entry:
            # No need to call out, can use manifest data directly
            return {'Download-Size': layer_entry['size'], 'BlobSum': layer_entry['digest'],
                    'Date': ';', 'Last-Modified': '',
                    'ETag': ''}

        for url in layer_entry.get('urls',[]):
            # Check for layer urls first
            response = self._client.get_blob_meta(self.name, url)
            if response and response.get('StatusCode') == 200:
                break
        else:
            # None,
            blobsum = layer_entry.get('blobSum', None)
            if not blobsum:
                return {}
            response = self._client.get_blob_meta(self.name, blobsum)

        return {'Download-Size': response.get('Content-Length', 'unknown'), 'BlobSum': blobsum,
                'Date': response.get('Date', ''), 'Last-Modified': response.get('Last-Modified', ''),
                'ETag': response.get('ETag', '').strip('"')}

def Repository(client, *args, **kwargs):
    if client.version == 1:
        return RepositoryV1(client, *args, **kwargs)
    else:
        assert client.version == 2
        return RepositoryV2(client, *args, **kwargs)
