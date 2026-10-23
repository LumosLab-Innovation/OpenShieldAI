"""Fixed local Unix-socket adapter; no public admin endpoint."""
import http.client
import json
import socket
import sys


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect('/admin/caddy.sock')


def main():
    request = json.load(sys.stdin)
    if set(request) - {'operation', 'route', 'etag'}:
        raise ValueError('unknown adapter fields')
    operation = request.get('operation')
    connection = UnixConnection('localhost', timeout=5)
    if operation == 'read':
        connection.request('GET', '/config/')
    elif operation == 'replace_route':
        if not isinstance(request.get('etag'), str) or len(request['etag']) > 200:
            raise ValueError('expected root etag required')
        connection.request('PATCH', '/config/apps/http/servers/shield/routes/0',
                           json.dumps(request['route']), {'Content-Type': 'application/json', 'If-Match': request['etag']})
    else:
        raise ValueError('unknown adapter operation')
    response = connection.getresponse()
    body = response.read(2_000_000)
    print(json.dumps({'status': response.status, 'etag': response.getheader('Etag'),
                      'config': json.loads(body) if response.status == 200 and body else None}))


if __name__ == '__main__':
    main()
