#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (c) 2015 Maciej Urbański <rooter@kyberian.net>
from sys import stderr
import time
import random
import string
import uuid
import os.path
import functools
import base64
import json
from collections import OrderedDict

import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.options

try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    stderr.write("Warning, GPIO will be mocked!\n")

    class MockCalls(object):
        def __getattribute__(self, item):
            def method(self, *args, **kwargs):
                stderr.write("called GPIO.%s(args=%s, kwargs=%s)\n" % (item,
                                                                       args,
                                                                       kwargs))
                return None

            return method

    GPIO = MockCalls()


def random_word(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))


def unpadded_base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


class OutputTicker(object):
    def __init__(self, gpio_no=0, resting_state=1):
        self.gpio_no = gpio_no
        self.resting_state = resting_state

        self.recompute_rhash()

        GPIO.setmode(GPIO.BCM)
        GPIO.setup(self.gpio_no, GPIO.OUT)
        self.set(self.resting_state)

    def set(self, state):
        GPIO.output(self.gpio_no, state)

    def tick(self, duration=0.5):
        self.set(not self.resting_state)
        time.sleep(duration)
        self.set(self.resting_state)

    def check_rhash(self, rhash):
        return rhash == self.rhash

    def recompute_rhash(self):
        self.rhash = random_word(6)
        return self.rhash


class Session(object):
    def __init__(self):
        self.id = uuid.uuid1()
        self.timestamp = time.time()
        self.user = None
        self.store = dict()


class SessionStore(object):
    def __init__(self, session_timeout=3600 * 24 * 30):
        self.session_timeout = session_timeout
        self.sessions = OrderedDict()

    def new_session(self):
        session = Session()
        self.sessions[session.id] = session
        return session

    def get_session(self, sid):
        self._invalid_old_sessions()
        return self.sessions[sid]

    def _invalid_old_sessions(self):
        for sid, session in self.sessions.items():
            if session.timestamp + self.session_timeout > time.time():
                break
            del self.sessions[sid]


class AccessControlList(object):
    def __init__(self):
        self.authorized = dict()

    def add_user(self, user):
        self.authorized[user] = None

    def remove_user(self, user):
        del self.authorized[user]

    def is_authorized(self, user):
        return user in self.authorized


class BaseHandler(tornado.web.RequestHandler):
    @property
    def sessions(self):
        return self.application.sessions

    def get_current_user(self):
        user = None
        sid_str = self.get_secure_cookie("sid")

        if sid_str:
            sid = uuid.UUID(sid_str)
            try:
                session = self.sessions.get_session(sid)
                user = session.user
            except KeyError:
                # session expired or mangled session id
                self.clear_cookie("sid")

        return user

    @staticmethod
    def authorized(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            if not self.application.acl.is_authorized(self.current_user):
                self.clear_cookie("sid")
                raise tornado.web.HTTPError(403)
            return method(self, *args, **kwargs)

        return wrapper


class AuthLoginHandler(BaseHandler, tornado.auth.GoogleOAuth2Mixin):
    @tornado.gen.coroutine
    def get(self):
        redirect_uri = "%s://%s%s" % (self.request.protocol,
                                      self.request.host,
                                      self.request.path)

        if self.get_argument('code', False):
            user = yield self.get_authenticated_user(
                redirect_uri=redirect_uri,
                code=self.get_argument('code'))

            # Please note we aren't verifing payload signature as we expect
            # it to be delivered by already verified source - in this case
            # Google service over HTTPS.
            id_token = user["id_token"]
            _h, payload_segment, _s = id_token.rsplit(b'.', 2)
            payload_js = unpadded_base64url_decode(
                payload_segment.encode("utf-8"))
            payload = json.loads(payload_js)

            if payload["email_verified"]:
                session = self.sessions.new_session()
                session.user = payload["email"]
                self.set_secure_cookie("sid", str(session.id))

            self.redirect(self.get_argument("next", "/"))
        else:
            yield self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings["google_oauth"]["key"],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("sid")
        self.redirect(self.get_argument("next", "/"))


class TickerHandler(BaseHandler):
    def initialize(self):
        self.rhash = None

    @property
    def ticker(self):
        return self.application.ticker

    @tornado.web.authenticated
    @BaseHandler.authorized
    def get(self, rhash):
        if self.ticker.check_rhash(rhash):
            self.render("clicky_pause.html")
            self.ticker.recompute_rhash()
            self.ticker.tick()
        else:
            self.render("clicky.html", code=self.ticker.rhash)


class Application(tornado.web.Application):
    def __init__(self, gpio, **settings):
        handlers = [
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/([^/]*)", TickerHandler),
        ]
        app_settings = dict(
            site_title=u"Garage Clicker",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            # random secret, assuming we don't store sessions
            cookie_secret=base64.b64encode(os.urandom(50)),
            login_url="/auth/login",
            autoreload=True
        )
        app_settings.update(settings)
        tornado.web.Application.__init__(self, handlers, **app_settings)

        self.ticker = OutputTicker(gpio)
        self.sessions = SessionStore()
        self.acl = AccessControlList()

    def add_user(self, user_email):
        self.acl.add_user(user_email)


if __name__ == "__main__":
    GPIO.setwarnings(
        False)  # enable during debug, but can throw warning on first gpio use

    options = tornado.options.OptionParser()
    options.define("config", default="garage_clicker.conf",
                   help="specify config filepath",
                   type=str)

    options.define("port", default=8888,
                   help="run on the given port",
                   type=int)

    options.define("debug", default=False,
                   type=bool, group="application")
    options.define("google_oauth",
                   help="should contain key and secret",
                   type=dict, group="application")
    options.define("gpio", default=0,
                   help="RPi GPIO port in GPIO.BCM scheme",
                   type=int, group="application")
    options.define("authorized",
                   help="list of authorized google accounts",
                   type=str, multiple=True)

    options.parse_command_line(final=False)
    options.parse_config_file(options.config, final=False)
    options.parse_command_line()

    app = Application(**options.group_dict("application"))
    for email in options.authorized:
        app.add_user(email)

    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
