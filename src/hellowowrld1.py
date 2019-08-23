from tornado.web import RequestHandler
import logging

class HelloWorld(RequestHandler):
    """Print 'Hello, world!' as the response body."""

    def get(self):
        """Handle a GET request for saying Hello World!."""
        logging.info('In Hello world handler')
        self.write("Hello, world!")