import logging
import os
import tornado.web
import tornado.log
from jose import jwt

import cookies

class ValidateHandler(tornado.web.RequestHandler):

    def __init__(self, *args, **kwargs):
        super(ValidateHandler, self).__init__(*args, **kwargs)

    def compute_etag(self):
        return None

    def get(self):
        id_token = self.get_secure_cookie(cookies.AUTH_COOKIE_NAME)
        if id_token:
            claims = jwt.get_unverified_claims(it_token)
            logging.debug('Secure cookie ok for user %s', claims['name'])
            self.set_header('auth-oid', claims.get('oid', ''))
            self.set_header('auth-name', claims.get('name', ''))
            self.set_header('auth-family-name', claims.get('family-name', ''))
            self.set_header('auth-given-name', claims.get('given-name', ''))
            self.set_header('auth-upn', claims.get('upn', ''))
            self.set_header('auth-email', claims.get('email', ''))
            self.set_header('auth-roles', claims.get('roles', ''))
            self.set_header('auth-jwt', id_token)
            self.set_status(200) #OK
        else:
            logging.info('Secure cookie not found. Either not logged in, cookie has expired, or cookie not valid.')
            self.set_header('Cache-Control', 'no-cache')
            self.set_status(401) #Unauthorized