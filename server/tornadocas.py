import re
import urllib
from tornado.web import RequestHandler, HTTPError
import config


'''
Just redirect to cas server to got the server ticket.
'''


class LoginHandler(RequestHandler):

    def get(self):

        # redirect to cas server
        redirect_url = config.get('cas_server') + '/login?service=' + \
            config.get('service_url')
        self.redirect(redirect_url)


'''
Validate the SERVER TICKET, return None if failed, otherwise userid.
'''


class DealWithSTHandler(RequestHandler):

    def get(self):

            # what you finally get
            userid = None

            try:
                server_ticket = self.get_argument('ticket')
            except Exception, e:
                print 'there is not server ticket in request argumets!'
                print e
                raise HTTPError(404)

            # validate the ST
            validate_suffix = '/proxyValidate'
            if config.get('version') == 1:
                validate_suffix = '/validate'

            validate_url = config.get('cas_server') + validate_suffix + \
                '?service=' + urllib.quote(config.get('service_url')) + \
                '&ticket=' + urllib.quote(server_ticket)

            response = urllib.urlopen(validate_url).read()
            pattern = r'<cas:user>(.*)</cas:user>'
            match = re.search(pattern, response)

            if match:
                    userid = match.groups()[0]
            if not userid:
                    print 'validate failed!'
                    raise HTTPError(404)

            self.deal_with_userid(userid)

    def deal_with_userid(self, userid):
            pass
