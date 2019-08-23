import logging
import os
import tornado.log
import tornado.web
import uuid
import base64
import json
import urllib
from jose import jwt
from jose.exceptions import JOSEError

import cookies

TEMPLATE_AUTHZ_URL = "{}?response_type=id_token&response_mode=form_post&client_id={}&redirect_uri={}&scope=openid&state={}&nonce={}"

class LoginHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(LoginHandler, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)

    def initialize(self, authorization_endpoint, issuer, client_id, redirect_uri, session_expire_days, jwks):
        logging.info('Login handler initialization')
        self.authorization_endpoint = authorization_endpoint
        self.issuer = issuer
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.session_expire_days = session_expire_days
        self.jwks = jwks

    def get(self):
        logging.info('In Hello world handler')
        self.write("Hello, world3!")
        #next_url = self.request.headers.get('X-Original-URI', '')
        next_url = 'https://www.google.com'
        self.write(next_url)

        #nonce = base64.b64encode((os.urandom(50)).decode('ascii'))
        nonce = '2345'

        state = self._serialize_state({
            'state_id': uuid.uuid4().hex,
            'next_url': next_url,
            'nonce': nonce
        })

        self.set_secure_cookie(cookies.STATE_COOKIE_NAME, state, expires_days=1, httponly=True)

        authorization_url = TEMPLATE_AUTHZ_URL.format(
            self.authorization_endpoint,
            self.client_id,
            self.redirect_uri,
            state,
            urllib.parse.quote(nonce)
        )

        self.redirect(authorization_url)

    def post(self):
        self.clear_cookie(cookies.AUTH_COOKIE_NAME)

        error = self.get_argument("error", False)
        if error:
            message = self.get_argument("error_description", error)

        if not self.get_argument("id_token", False):
            raise tornado.web.HTTPError(400, "OAuth callback made without an id_token")
        id_token = self.get_argument("id_token", None)

        state_cookie = (self.get_secure_cookie(cookies.STATE_COOKIE_NAME) or b'').decode('utf8', 'replace')
        self.clear_cookie(cookies.STATE_COOKIE_NAME)
        url_state = self.get_argument("state", None)

        try:
            token = jwt.decode(id_token, self.jwks(), audience=self.client_id, issuer=self.issuer)
        except JOSEError as e:
            self.logger.warning("OAuth jwt decode failed: %s : token %s", e, id_token)
            raise tornado.web.HTTPError(400, "OAuth jwt decode failed")

        next_url = self._deserialize_state(url_state).get('next_url')

        self.set_secure_cookie(cookies.AUTH_COOKIE_NAME, id_token, expires_days=self.session_expire_days)

        if next_url:
            logging.info('Login succeeded for user %s. Redirecting to %s', token['name'], next_url)
            self.redirect(next_url)
        else:
            logging.info('Login succeeded for user %s. No redirect url', token['name'])
            self.set_status(200)

    def _serialize_state(self, state):
        json_state = json.dumps(state)
        return base64.urlsafe_b64encode(
            json_state.encode('utf8')
        ).decode('ascii')

    def _deserialize_state(self, b64_state):
        if isinstance(b64_state, str):
            b64_state = b64_state.encode('ascii')
        try:
            json_state = base64.urlsafe_b64decode(b64_state).decode('utf8')
        except ValueError:
            self.logger.error("Failed to b64-decode state: %r", b64_state)
            return {}
        try:
            return json.loads(json_state)
        except ValueError:
            self.logger.error("Failed to json-decode state: %r", json_state)
            return {}
