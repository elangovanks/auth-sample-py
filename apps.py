import base64
import logging
import os
import tornado.log
import tornado.web

import login
import validate
import jwksprovider

logging.basicConfig(
    format="%(ascitime)s [%(process)d] %(name)s - %(levelname)s - %(messages)s",
    level=logging.INFO
)

tornado.log.enable_pretty_logging()

def read_settings():
    settings = {
        'authorization_endpoint': "https://login.microsoftonline.com/ba5c8ffb-b616-44b1-9794-989a110c71c9/oauth2/authorize",
        'jwks_uri': "https://login.microsoftonline.com/common/discovery/keys",
        'issuer': "https://sts.windows.net/ba5c8ffb-b616-44b1-9794-989a110c71c9/",
        'client_id': "fe4f6294-97c4-410f-89f6-fd3311bbb260",
        'redirect_uri': "http://localhost:8080/api/auth/v1/login",
    }

    if os.environ.get('COOKIE_SECRET'):
        settings['secret'] = os.environ['COOKIE_SECRET']
    else:
        logging.info('Getting new random cookie secret')
        settings['secret'] = base64.b64encode(os.urandom(50)).decode('ascii')

    if os.environ.get('SESSION_EXPIRE_DAYS'):
        settings['session_expire_days'] = os.environ['SESSION_EXPIRE_DAYS']
    else:
        logging.info('setting session_expire_days to 1')
        settings['session_expire_days'] = 1

    return settings

def get_jwks_provider(settings):
    return jwksprovider.JwksProvider(settings['jwks_uri'])

def get_app(settings, jwks_provider):
    return tornado.web.Application(handlers=[
        (r"/api/auth/v1/login", login.LoginHandler, {
            'authorization_endpoint': settings['authorization_endpoint'],
            'issuer': settings['issuer'],
            'client_id': settings['client_id'],
            'redirect_uri': settings['redirect_uri'],
            'session_expire_days': settings['session_expire_days'],
            'jwks': jwks_provider.get_jwks}),
        (r"/api/auth/v1/validate", validate.ValidateHandler),
    ], cookie_secret = settings['secret'])


if __name__ == '__main__':
    settings = read_settings()
    jwks_provider = get_jwks_provider(settings)
    apps = get_app(settings, jwks_provider)

    tornado.ioloop.IOLoop.current().run_sync(jwks_provider.update)
    tornado.ioloop.IOLoop.current().spawn_callback(jwks_provider.update_loop)

    http_server = tornado.httpserver.HTTPServer(apps)
    http_server.listen(8080)

    logging.info('Listening on port 8000')

    tornado.ioloop.IOLoop.current().start()
