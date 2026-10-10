import ssl

import aiohttp
import pytest

from fakepve import FakePve, settle
from fakepve.certs import make_cert


@pytest.fixture(scope='session')
def cert(tmp_path_factory):
    return make_cert(str(tmp_path_factory.mktemp('pki')))


@pytest.fixture
async def pve(cert):
    fake = FakePve(user='root@pam', password='secret')
    await fake.start(cert[0], cert[1])
    yield fake
    await settle()
    await fake.stop()


class Client(object):
    """A small PVE API client: logs in, sends CSRF on writes, returns (status, json)."""

    def __init__(self, session):
        self.session = session
        self.headers = {}

    async def login(self, user='root@pam', password='secret'):
        status, body = await self.call('POST', '/access/ticket', {'username': user, 'password': password})
        if status == 200:
            data = body['data']
            self.headers = {'Cookie': 'PVEAuthCookie=' + data['ticket'],
                            'CSRFPreventionToken': data['CSRFPreventionToken']}
        return status, body

    async def call(self, method, path, data=None):
        kwargs = {'headers': self.headers}
        if data is not None:
            kwargs['json' if method != 'POST' or path != '/access/ticket' else 'data'] = data
        async with self.session.request(method, '/api2/json' + path, **kwargs) as rsp:
            return rsp.status, await rsp.json(content_type=None)

    async def data(self, method, path, data=None):
        status, body = await self.call(method, path, data)
        assert status == 200, (status, body)
        return body['data']


@pytest.fixture
async def api(pve):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession(base_url='https://{0}:{1}'.format(pve.host, pve.port),
                                     connector=aiohttp.TCPConnector(ssl=ctx)) as session:
        client = Client(session)
        await client.login()
        yield client
