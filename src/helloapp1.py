from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.options import define, options
from tornado.web import Application
import hellowowrld1

define('port', default=8080, help='port to listen on')

def get_app():
    return Application(handlers=[
        (r"/hello1", hellowowrld1.HelloWorld),
    ])


if __name__ == '__main__':
    """Construct and serve the tornado application."""
    app = get_app()
    http_server = HTTPServer(app)
    http_server.listen(options.port)
    print('Listening on http://localhost:%i' % options.port)
    IOLoop.current().start()