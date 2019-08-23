import logging
import os
import tornado.log
import tornado.web
import uuid
import base64
import json
from jose import jwt

import cookies

class LogoutHandler(tornado.web.RequestHandler):

    def __init__(self, *args, **kwargs):
        super(LogoutHandler, self).__init__(*args, **kwargs)

    def get(self):
        id_token = self.get_secure_cookie(cookies.AUTH_COOKIE_NAME)
        if id_token:
            claims = jwt.get_unverified_claims(id_token)
            logging.info('Logging out user %s', claims['name'])
        else:
            logging.info('Logging out unknow user')

        self.clear_cookie(cookies.AUTH_COOKIE_NAME)

        self.redirect('https://login.microsoftonline.com/common/oauth2/logout')