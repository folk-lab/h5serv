##############################################################################
# Copyright by The HDF Group.                                                #
# All rights reserved.                                                       #
#                                                                            #
# This file is part of H5Serv (HDF5 REST Server) Service, Libraries and      #
# Utilities.  The full HDF5 REST Server copyright notice, including          #
# terms governing use, modification, and redistribution, is contained in     #
# the file COPYING, which can be found at the root of the source code        #
# distribution tree.  If you do not have access to this file, you may        #
# request a copy from help@hdfgroup.org.                                     #
##############################################################################

import hdf5plugin
import largeImages
import permissions
from pwd import getpwnam
from grp import getgrall, getgrgid
import stat
import numpy
import time
import signal
import logging
import logging.handlers
import os
import os.path as op
import tornado.httpserver
import sys
import ssl
import base64
# import binascii
from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application, url, HTTPError
from tornado.escape import json_encode, json_decode, url_escape, url_unescape
from h5json import Hdf5db
import h5json
import config
from timeUtil import unixTimeToUTC
import fileUtil
import tocUtil
from httpErrorUtil import errNoToHttpStatus
from h5watchdog import h5observe
from passwordUtil import getAuthClient
import urllib
import json
import six
if six.PY3:
    unicode = str
    from queue import Queue
else:
    from Queue import Queue


assert hdf5plugin  # silence pyflakes


def to_bytes(a_string):
    if type(a_string) is unicode:
        return a_string.encode('utf-8')
    else:
        return a_string


def to_str(a_string):
    if type(a_string) is bytes:
        return a_string.decode('utf-8')
    else:
        return a_string


class DefaultHandler(RequestHandler):
    def put(self):
        log = logging.getLogger("h5serv")
        log.warning("got default PUT request")
        log.info('remote_ip: ' + self.request.remote_ip)
        log.warning(self.request)
        raise HTTPError(400, reason="No route matches")

    def get(self):
        log = logging.getLogger("h5serv")
        log.warning("got default GET request")
        log.info('remote_ip: ' + self.request.remote_ip)
        log.warning(self.request)
        raise HTTPError(400, reason="No route matches")

    def post(self):
        log = logging.getLogger("h5serv")
        log.warning("got default POST request")
        log.info('remote_ip: ' + self.request.remote_ip)
        log.warning(self.request)
        raise HTTPError(400, reason="No route matches")

    def delete(self):
        log = logging.getLogger("h5serv")
        log.warning("got default DELETE request")
        log.info('remote_ip: ' + self.request.remote_ip)
        log.warning(self.request)
        raise HTTPError(400, reason="No route matches")


class BaseHandler(tornado.web.RequestHandler):

    """
    Enable CORS
    """
    def set_default_headers(self):
        cors_domain = config.get('cors_domain')
        self.log = logging.getLogger("h5serv")
        self.log.info('cors_domain: ' + str(cors_domain))
        if cors_domain:
            self.set_header('Access-Control-Allow-Origin', cors_domain)
            self.set_header('Access-Control-Allow-Credentials', 'true')

    """
    Set allows heards per CORS policy
    """
    def options(self):
        cors_domain = config.get('cors_domain')
        if cors_domain:
            self.set_header('Access-Control-Allow-Headers', 'Content-type,')

    """
    Override of Tornado get_current_user
    """
    def get_current_user(self):

        # Initialize variables
        self.username = None
        self.userid = -1
        self.usergroupids = []
        self.userattributes = None

        self.log = logging.getLogger("h5serv")
        self.log.info('BaseHandler.get_current_user')

        # Look at page header information - a 'Cookie' might be in there
        # somewhere
        self.log.info("header keys...")
        for k in self.request.headers.keys():
            self.log.info("header[" + k + "]: " + self.request.headers[k])
        self.log.info('remote_ip: ' + self.request.remote_ip)

        # See if there is a specific cookie with CAS information in it
        attributes = self.get_secure_cookie('cas_attributes')
        if attributes:
            attributes = json.loads(attributes)
        self.log.info(attributes)
        self.log.info(bool(attributes))
        self.userattributes = attributes

        if attributes:

            self.username = attributes['userName']
            self.log.info('self.username: ' + str(self.username))

            # Get user id number from the server machine - quick fix, should
            # really get this from CAS, but that item is not available at this
            # time
            self.userid = getpwnam(self.username).pw_uid
            self.log.info('self.userid: ' + str(self.userid))

            # Get the groups for this user - also a quick fix
            self.usergroupids = [g.gr_gid for g in getgrall() if self.username
                                 in g.gr_mem]
            gid = getpwnam(self.username).pw_gid
            self.usergroupids.append(getgrgid(gid).gr_gid)

            self.log.info('gid: ' + str(gid))
            self.log.info('self.usergroupids: ' + str(self.usergroupids))

            for key, value in attributes.iteritems():
                self.log.info('attributes[' + str(key) + ']: ' +
                              str(value))

            return True

        self.log.info('no logged in user')

        return None

    # def get_current_user(self):
    #     user = None
    #     pswd = None
    #     # scheme, _, token = auth_header = self.request.headers.get(
    #     scheme, _, token = self.request.headers.get(
    #         'Authorization', '').partition(' ')
    #     if scheme and token and scheme.lower() == 'basic':
    #         try:
    #             if six.PY3:
    #                 token_decoded = base64.decodebytes(to_bytes(token))
    #             else:
    #                 token_decoded = base64.decodestring(token)
    #         except binascii.Error:
    #             raise HTTPError(400, "Malformed authorization header")
    #         if token_decoded.index(b':') < 0:
    #             raise HTTPError(400, "Malformed authorization header")
    #         user, _, pswd = token_decoded.partition(b':')
    #     if user and pswd:
    #         # throws exception if passwd is not valid
    #         self.username = user
    #         self.userid = auth.validateUserPassword(user, pswd)
    #         return self.userid
    #     else:
    #         self.username = None
    #         self.userid = -1
    #         return None

    def verifyAcl(self, acl, action):
        """Verify ACL for given action. Raise exception if not
        authorized.

        """
        if acl[action]:
            return
        if self.userid <= 0:
            self.set_status(401)
            self.set_header('WWW-Authenticate', 'basic realm="h5serv"')
            raise HTTPError(401, "Unauthorized")
            # raise HTTPError(401, message="provide  password")

        # validated user, but doesn't have access
        self.log.info("unauthorized access for userid: " + str(self.userid))
        raise HTTPError(403, "Access is not permitted")

    """
    baseHandler - log request and set state to be used by method implementation
    """
    def baseHandler(self, checkExists=True):

        # Output request URI to log
        self.log = logging.getLogger("h5serv")

        protocol = self.request.protocol
        if "X-Forwarded-Proto" in self.request.headers:
            protocol = self.request.headers["X-Forwarded-Proto"]

        host = self.request.host
        if "X-Forwarded-Host" in self.request.headers:
            host = self.request.headers["X-Forwarded-Host"]

        self.domain = self.get_query_argument("host", default=None)

        if not self.domain:
            self.domain = host
        remote_ip = self.request.remote_ip
        if "X-Real-Ip" in self.request.headers:
            remote_ip = self.request.headers["X-Real-Ip"]

        # sets self.userid, self.username
        self.get_current_user()
        self.filePath = self.getFilePath(self.domain, checkExists)
        self.log.info("self.filePath: " + self.filePath)

        self.reqUuid = self.getRequestId()
        self.log.info("self.reqUuid: " + str(self.reqUuid))
        # if self.reqUuid is None and self.filePath is not None:
        #     with Hdf5db(self.filePath, app_logger=self.log) as db:
        #         self.reqUuid = db.getUUIDByPath(self.filePath)
        # # if self.reqUuid is not None:
        # #     with Hdf5db(self.filePath, app_logger=self.log) as db:
        # #         db.getPathByUUID(self.reqUuid)

        # get file permisssions and ownership, set ACL
        if self.reqUuid is not None:
            can_user_read_file = self.can_user_read_file(self.filePath)
            self.log.info('can_user_read_file: ' + str(can_user_read_file))
            self.set_file_ACL(can_user_read_file)

        self.href = protocol + '://' + host
        self.log.info("baseHandler, href: " + self.href)
        msg = "REQ " + self.request.method + " " + self.href + self.request.uri
        msg += " {remote_ip: " + remote_ip
        if self.username is not None:
            msg += ", username: " + to_str(self.username)
        msg += "}"
        self.log.info(msg)

    '''
    Look at the ownership and permissions of a file and determine if the logged
    in user has read access or not - ignore write access for now.
    '''
    def can_user_read_file(self, filepath):

        self.log.info("actual file?: " + filepath)

        readable_as_owner = False
        readable_by_group = False
        readable_by_other = False

        # Ignore the table of contents file
        if filepath.endswith(config.get('toc_name')):
            return False

        # Ignore dot files - per file table of contents files

        # Get the owner and group ids, mode, and a bunch of other information
        # about the file
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = \
            os.stat(filepath)

        # Check if this is a file or directory
        self.log.info('stat.S_ISDIR(mode): ' + str(stat.S_ISDIR(mode)))
        self.log.info('stat.S_ISREG(mode): ' + str(stat.S_ISREG(mode)))
        self.log.info('stat.S_ISLNK(mode): ' + str(stat.S_ISLNK(mode)))

        # Check if the user is the owner and has read permissions
        if uid == self.userid:
            user_readable = bool(mode & stat.S_IRUSR)
            if user_readable:
                readable_as_owner = True

        # Check if the user is in the right group and has read permissions
        if gid in self.usergroupids:
            group_readable = bool(mode & stat.S_IRGRP)
            if group_readable:
                readable_by_group = True

        # Check if this file is readable by others
        readable_by_other = bool(mode & stat.S_IROTH)

        self.log.info('readable_as_owner: ' + str(readable_as_owner))
        self.log.info('readable_by_group: ' + str(readable_by_group))
        self.log.info('readable_by_other: ' + str(readable_by_other))

        if readable_as_owner or readable_by_group or readable_by_other:
            return True
        else:
            return False

    def set_file_ACL(self, can_user_read_file):

        self.log.info('set_file_ACL(' + str(can_user_read_file) + ')')
        self.log.info("self.filePath: " + self.filePath)

        # Ignore the table of contents file
        if self.filePath.endswith(config.get('toc_name')):
            return False

        with Hdf5db(self.filePath, app_logger=self.log) as db:
            acl = db.getDefaultAcl()
            acl['userid'] = self.userid
            fields = ('create', 'read', 'update', 'delete', 'readACL',
                      'updateACL')
            for field in fields:
                if field == 'read' and can_user_read_file:
                    acl[field] = True
                else:
                    acl[field] = False

            self.log.info('acl: ' + str(acl))
            self.log.info('self.reqUuid: ' + str(self.reqUuid))

            db.setAcl(self.reqUuid, acl)

    """
    getExternal uri - return url for given domain
       Use protocol and host of current request
    """
    def getExternalHref(self, domain, h5path=None):
        target = self.request.protocol
        if "X-Forwarded-Proto" in self.request.headers:
            target = self.request.headers["X-Forwarded-Proto"]
        target += '://'

        host = self.request.host
        if "X-Forwarded-Host" in self.request.headers:
            host = self.request.headers["X-Forwarded-Host"]
        hostQuery = self.get_query_argument("host", default=None)

        targetHostQuery = ''

        # url encode the domain
        domain = self.nameEncode(domain)
        if hostQuery or self.isTocFilePath(self.filePath):
            target += host
            targetHostQuery = '?host=' + domain
        else:
            target += domain

        if h5path is None or h5path == '/':
            target += '/'
        else:
            target += '/#h5path(' + h5path + ')'
        target += targetHostQuery

        return target

    """
    Convience method to compute href links
    """
    def getHref(self, uri, query=None):
        href = self.href + '/' + uri
        delimiter = '?'
        if self.get_query_argument("host", default=None):
            href += "?host=" + self.nameEncode(self.get_query_argument("host"))
            delimiter = '&'

        if query is not None:
            if type(query) is str:
                href += delimiter + query
            else:
                # list or tuple
                for item in query:
                    href += delimiter + item
                    delimiter = '&'
        return href

    def setDefaultAcl(self):
        """ Set default ACL for user TOC file.
        """
        log = logging.getLogger("h5serv")
        log.info("setDeaultAcl -- userid: " + str(self.userid))
        if self.userid <= 0:
            raise HTTPError(500, "Expected userid")
        # username = auth.getUserName(self.userid)
        username = self.username
        filePath = tocUtil.getTocFilePath(username)
        try:
            fileUtil.verifyFile(filePath)
        except HTTPError:
            log.info("toc file doesn't exist, returning")
            return
        try:
            with Hdf5db(filePath, app_logger=self.log) as db:
                acl = db.getDefaultAcl()
                acl['userid'] = self.userid
                fields = ('create', 'read', 'update', 'delete', 'readACL',
                          'updateACL')

                for field in fields:
                    # acl[field] = False
                    acl[field] = True

                obj_uuid = None

                self.log.info("acl: " + str(acl))

                db.setAcl(obj_uuid, acl)

        except IOError as e:
            log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

    def getFilePath(self, domain, checkExists=True):
        """ Helper method - return file path for given domain.
        """
        self.log.info("getFilePath: " + domain + " checkExists: " +
                      str(checkExists))
        tocFilePath = fileUtil.getTocFilePathForDomain(domain, auth)
        self.log.info("tocFilePath: " + tocFilePath)
        if not fileUtil.isFile(tocFilePath):
            tocUtil.createTocFile(tocFilePath)
            if self.userid > 0:
                # setup the permision to grant this user exclusive write access
                # and public read for everyone
                self.setDefaultAcl()

        filePath = fileUtil.getFilePath(domain, auth)

        # convert any "%2E" substrings with "." (since dot isn't allowed for
        # domain name)
        filePath = self.nameDecode(filePath)

        if checkExists:
            while True:
                if fileUtil.isFile(filePath):
                    break
                # Unfortunately the host query parameter substitues '/' for
                # "%2E", so check to see if any slashes should really be dots.
                # clients should prefer using the host header if this is an
                # issue
                self.log.info("filePath: " + filePath + " not found")
                host_query = self.get_query_argument("host", default=None)
                if host_query is None:
                    # If using host header, we don't need to guess about the
                    # %2E substitution
                    break
                if domain.find('.') > -1:
                    domain = domain.replace('.', '%2E', 1)
                    try:
                        filePath = fileUtil.getFilePath(domain, auth)
                    except HTTPError:
                        self.log.info("invalid domain, ignoring")
                        break
                    filePath = self.nameDecode(filePath)
                else:
                    break

            self.log.info("verifyFile: " + filePath)
            fileUtil.verifyFile(filePath)  # throws exception if not found

        return filePath

    def isWritable(self, filePath):
        """Helper method - raise 403 error if given file path is not writable
        """
        fileUtil.verifyFile(filePath, writable=True)

    def isTocFilePath(self, filePath):
        """Helper method - return True if this is a TOC file apth
        """
        if tocUtil.isTocFilePath(filePath):
            return True
        else:
            return False

    def nameDecode(self, name):
        """
        Helper function - convert url-encoded name to orignal format
        """
        name = name.replace('%2E', '.')
        return name

    def nameEncode(self, name):

        """
        Helper function - convert name to url-friendly format
        Replaces all non-alphanumeric characters with '%<ascii_hex>'
        """

        valid_chars = ['-', '.', '_', '~', ':', '/', '?', '#', '[', ']', '@',
                       '!', '$', '&', "'", '(', ')', '*', '+', ',', ';', '=']
        out = []
        for ch in name:
            if ch.isalnum():
                out.append(ch)
            elif ch == ' ':
                out.append('+')
            elif ch == '%':
                # pass through encoded chars ('%xx' where xx are hexidecimal
                # values)
                out.append(ch)
            elif ch in valid_chars:
                # other valid url chars
                out.append(ch)
            else:
                hex = format(ord(ch), '02X')
                out.append('%' + hex)

        return ''.join(out)

    def getRequestId(self):
        """
        Helper method - return request uuid from request URI
        URI' are of the form:
            /groups/<uuid>/xxx
            /datasets/<uuid>/xxx
            /datatypes/<uuid>/xxx
        extract the <uuid> and return it.
        Throw 500 error is the URI is not in the above form
        """

        uri = self.request.uri

        # strip off any query params
        npos = uri.find('?')
        if npos > 0:
            uri = uri[:npos]

        if uri.startswith('/groups/'):
            uri = uri[len('/groups/'):]  # get stuff after /groups/
        elif uri.startswith('/datasets/'):
            uri = uri[len('/datasets/'):]  # get stuff after /datasets/
        elif uri.startswith('/datatypes/'):
            uri = uri[len('/datatypes/'):]  # get stuff after /datatypes/
        else:

            # msg = "unexpected uri: " + uri
            # self.log.error(msg)
            # raise HTTPError(500, reason=msg)

            return None
        npos = uri.find('/')
        if npos < 0:
            uuid = uri
        elif npos == 0:
            msg = "Bad Request: uri is invalid"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        else:
            uuid = uri[:npos]

        self.log.info('got uuid: [' + uuid + ']')

        return uuid

    """
    Get requested content type.  Returns either "binary" if the accept header
    is octet stream, otherwise json.  Currently does not support q fields.
    """
    def getAcceptType(self):
        content_type = self.request.headers.get('Accept')
        if content_type:
            self.log.info("CONTENT_TYPE:" + content_type)
        if content_type == "application/octet-stream":
            return "binary"
        else:
            return "json"


class LinkCollectionHandler(BaseHandler):
    def get(self):
        self.baseHandler()

        # Get optional query parameters
        limit = self.get_query_argument("Limit", 0)
        if type(limit) is not int:
            try:
                limit = int(limit)
            except ValueError:
                msg = "Bad Request: Expected int type for limit"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        marker = self.get_query_argument("Marker", None)

        response = {}

        items = None
        rootUUID = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:

                self.log.info('self.filePath: ' + self.filePath)

                rootUUID = db.getUUIDByPath('/')
                current_user_acl = db.getAcl(self.reqUuid, self.userid)

                self.log.info('self.reqUuid: ' + str(self.reqUuid))
                db.getPathByUUID(self.reqUuid, 'groups')
                self.log.info('self.userid: ' + str(self.userid))
                self.log.info('current_user_acl: ' + str(current_user_acl))

                # throws exception is unauthorized
                self.verifyAcl(current_user_acl, 'read')
                items = db.getLinkItems(self.reqUuid, marker=marker,
                                        limit=limit)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response
        links = []
        hrefs = []

        hostQuery = ''
        if self.get_query_argument("host", default=None):
            hostQuery = "?host=" + self.get_query_argument("host")

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('groups/' + self.reqUuid + '/links')
        })
        for item in items:
            link_item = {}
            link_item['class'] = item['class']
            link_item['title'] = item['title']
            link_item['href'] = item['href'] = self.href + '/groups/' + \
                self.reqUuid + '/links/' + self.nameEncode(item['title']) + \
                hostQuery

            self.log.info('item: ' + str(item))
            parent_group_uuid = self.reqUuid
            self.log.info('parent_group_uuid: ' + str(parent_group_uuid))

            # Folders
            if item['class'] == 'H5L_TYPE_HARD':
                link_item['id'] = item['id']
                link_item['collection'] = item['collection']
                link_item['target'] = self.href + '/' + item['collection'] + \
                    '/' + item['id'] + hostQuery

                # Check the folder permissions, check if logged in user can
                # read the contents
                link_item['readable'] = permissions.get_info_from_uuid(
                    '../data/' + config.get('toc_name'), item['id'],
                    self.username, False)

            elif item['class'] == 'H5L_TYPE_SOFT':
                link_item['h5path'] = item['h5path']

            # Data files
            elif item['class'] == 'H5L_TYPE_EXTERNAL':
                link_item['h5path'] = item['h5path']
                h5domain = self.nameEncode(item['file'])
                link_item['h5domain'] = h5domain
                if link_item['h5domain'].endswith(config.get('domain')):
                    link_item['target'] = self.getExternalHref(
                        h5domain, link_item['h5path'])

                    # Not sure if this is the best place to have this:
                    # Check if the linked to item is readable by the logged in
                    # user, add that information to output
                    filepath = self.getFilePath(h5domain, True)
                    self.log.info("filepath: " + filepath)
                    link_item['readable'] = self.can_user_read_file(filepath)

            # If the item is not readable by the logged in user, don't add it
            # to the output
            if 'readable' in link_item:
                if link_item['readable']:
                    links.append(link_item)
            else:
                links.append(link_item)

        response['links'] = links

        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        home_dir = config.get("home_dir")
        hrefs.append({'rel': home_dir, 'href': self.getHref('')})
        hrefs.append({
            'rel': 'owner',
            'href': self.getHref('groups/' + self.reqUuid)
        })
        response['hrefs'] = hrefs
        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class LinkHandler(BaseHandler):
    def getName(self, uri):
        # helper method
        # uri should be in the form: /group/<uuid>/links/<name>
        # this method returns name
        npos = uri.find('/links/')
        if npos < 0:
            # shouldn't be possible to get here
            msg = "Internal Server Error: Unexpected uri"
            self.log.error(msg)
            raise HTTPError(500, reason=msg)
        if npos+len('/links/') >= len(uri):
            # no name specified
            msg = "Bad Request: no name specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        linkName = uri[npos+len('/links/'):]
        if linkName.find('/') >= 0:
            # can't have '/' in link name
            msg = "Bad Request: invalid linkname, '/' not allowed"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        npos = linkName.rfind('?')
        if npos >= 0:
            # trim off the query params
            linkName = linkName[:npos]

        linkName = url_unescape(linkName)
        return linkName

    def get(self):
        self.baseHandler()

        linkName = self.getName(self.request.uri)

        self.log.info("linkName:["+linkName+"]")

        response = {}

        rootUUID = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getLinkItemByUuid(self.reqUuid, linkName)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        response['lastModified'] = unixTimeToUTC(item['mtime'])
        response['created'] = unixTimeToUTC(item['ctime'])
        for key in ('mtime', 'ctime', 'href'):
            if key in item:
                del item[key]

        # replace 'file' key by 'h5domain' if present
        if 'file' in item:
            h5domain = item['file']
            del item['file']
            item['h5domain'] = self.nameEncode(h5domain)

        response['link'] = item

        hrefs = []
        hrefs.append({
            'rel': 'self',
            'href': self.getHref('groups/' + self.reqUuid + '/links/' +
                                 url_escape(linkName))
        })
        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        hrefs.append({
            'rel': 'home', 'href': self.getHref('')
        })
        hrefs.append({
            'rel': 'owner',
            'href': self.getHref('groups/' + self.reqUuid)
        })

        target = None
        if item['class'] == 'H5L_TYPE_HARD':
            target = self.getHref(item['collection'] + '/' + item['id'])
        elif item['class'] == 'H5L_TYPE_SOFT':
            target = self.getHref('/#h5path(' + item['h5path'] + ')')
        elif item['class'] == 'H5L_TYPE_EXTERNAL':
            if item['h5domain'].endswith(config.get('domain')):
                target = self.getExternalHref(h5domain, item['h5path'])

        if target:
            hrefs.append({'rel': 'target', 'href': target})

        response['hrefs'] = hrefs
        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def put(self):
        self.baseHandler()

        # put - create a new link
        # patterns are:
        # PUT /groups/<id>/links/<name> {id: <id> }
        # PUT /groups/<id>/links/<name> {h5path: <path> }
        # PUT /groups/<id>/links/<name> {h5path: <path>, h5domain: <href> }

        linkName = self.getName(self.request.uri)

        body = None
        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            msg = "JSON Parser Error: " + e.message
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        childUuid = None
        h5path = None
        h5domain = None
        # filename = None   # fake filename

        if "id" in body:
            childUuid = body["id"]
            if childUuid is None or len(childUuid) == 0:
                msg = "Bad Request: id not specified"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        elif "h5path" in body:
            # todo
            h5path = body["h5path"]
            if h5path is None or len(h5path) == 0:
                raise HTTPError(400)

            # if h5domain is present, this will be an external link
            if "h5domain" in body:
                h5domain = body["h5domain"]
        else:
            msg = "Bad request: missing required body keys"
            self.log.info(msg)
            raise HTTPError(400, reasoln=msg)

        if self.isTocFilePath(self.filePath):
            msg = "Forbidden: links can not be directly created in TOC domain"
            self.log.info(msg)
            raise HTTPError(403, reason=msg)

        response = {}

        rootUUID = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'create')
                try:
                    existingItem = db.getLinkItemByUuid(self.reqUuid, linkName)
                    if existingItem:
                        # link alread exist
                        msg = "Unable to create link (Name already exists)"
                        self.log.info(msg)
                        raise HTTPError(409, reason=msg)
                except IOError as e:
                    # link not found, so we can add one with this name
                    pass

                if childUuid:
                    db.linkObject(self.reqUuid, childUuid, linkName)
                elif h5domain:
                    db.createExternalLink(self.reqUuid, h5domain, h5path,
                                          linkName)
                elif h5path:
                    db.createSoftLink(self.reqUuid, h5path, linkName)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        hrefs = []

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('groups/' + self.reqUuid + '/links/' +
                                 url_escape(linkName))
        })
        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        hrefs.append({
            'rel': 'home',
            'href': self.getHref('')
        })
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('groups/' + self.reqUuid)})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)

    def delete(self):
        self.baseHandler()

        linkName = self.getName(self.request.uri)

        response = {}
        rootUUID = None

        self.isWritable(self.filePath)
        if self.isTocFilePath(self.filePath):
            msg = "Forbidden: links can not be directly modified in TOC domain"
            self.log.info(msg)
            raise HTTPError(403, reason=msg)
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'delete')
                db.unlinkItem(self.reqUuid, linkName)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        hrefs = []

        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('groups/' + self.reqUuid)})

        response['hrefs'] = hrefs
        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class AclHandler(BaseHandler):
    def getRequestCollectionName(self):
        # request is in the form
        # /(datasets|groups|datatypes)/<id>/acls(/<username>), or
        # /acls(/<username>) for domain acl return datasets | groups |
        # datatypes
        uri = self.request.uri

        npos = uri.find('/')
        if npos < 0:
            self.log.info("bad uri")
            raise HTTPError(400)
        if uri.startswith('/acls/'):
            # domain request - return group collection
            return 'groups'

        uri = uri[(npos+1):]

        npos = uri.find('/')  # second '/'
        if npos < 0:
            # uri is "/acls"
            return "groups"
        col_name = uri[:npos]

        self.log.info('got collection name: [' + col_name + ']')
        if col_name not in ('datasets', 'groups', 'datatypes'):
            msg = "Internal Server Error: collection name unexpected"
            self.log.error(msg)
            # shouldn't get routed here in this case
            raise HTTPError(500, reason=msg)

        return col_name

    def getName(self):
        uri = self.request.uri

        if uri.endswith('/acls'):
            return None  # default domain acl
        # helper method
        # uri should be in the form: /group/<uuid>/acl/<username>
        # this method returns name
        npos = uri.find('/acls/')
        if npos < 0:
            # shouldn't be possible to get here
            msg = "Internal Server Error: Unexpected uri"
            self.log.error(msg)
            raise HTTPError(500, reason=msg)
        if npos+len('/acls/') >= len(uri):
            # no name specified
            msg = "Bad Request: no name specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        userName = uri[npos+len('/acls/'):]
        if userName.find('/') >= 0:
            # can't have '/' in link name
            msg = "Bad Request: invalid linkname, '/' not allowed"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        npos = userName.rfind('?')
        if npos >= 0:
            # trim off the query params
            userName = userName[:npos]
        return userName

    def convertUserIdToUserName(self, acl_in):
        """
        convertUserIdToUserName - replace userids with username
        """
        acl_out = None
        if type(acl_in) in (list, tuple):
            # convert list to list
            acl_out = []
            for item in acl_in:
                acl_out.append(self.convertUserIdToUserName(item))
        else:
            acl_out = {}
            for key in acl_in.keys():
                if key == 'userid':
                    # convert userid to username
                    userid = acl_in['userid']

                    user_name = '???'
                    if userid == 0:
                        user_name = 'default'
                    else:
                        user_name = auth.getUserName(userid)
                        if user_name is None:
                            self.log.warning("user not found for userid: " +
                                             str(userid))
                    acl_out['userName'] = user_name
                else:
                    value = acl_in[key]
                    acl_out[key] = True if value else False
        return acl_out

    def get(self):
        self.baseHandler()

        req_uuid = None
        if not self.request.uri.startswith("/acls"):
            # get UUID for object unless this is a get on domain acl
            req_uuid = self.getRequestId()

        rootUUID = None
        # filePath = self.getFilePath(self.domain)
        userName = self.getName()

        col_name = self.getRequestCollectionName()

        req_userid = None
        if userName:
            if userName == 'default':
                req_userid = 0
            else:
                req_userid = auth.getUserId(userName)
                if req_userid is None:
                    # username not found
                    msg = "username does not exist"
                    self.log.info(msg)
                    raise HTTPError(404, reason=msg)

        # request = {}
        acl = None
        current_user_acl = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                if req_uuid:
                    obj_uuid = req_uuid
                else:
                    obj_uuid = rootUUID

                current_user_acl = db.getAcl(obj_uuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(current_user_acl, 'readACL')
                if req_userid is None:
                    acl = db.getAcls(obj_uuid)
                else:
                    acl = db.getAcl(obj_uuid, req_userid)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        response = {}
        acl = self.convertUserIdToUserName(acl)

        if userName is None:
            userName = ''  # for string concat in the hrefs
            response['acls'] = acl
        else:
            response['acl'] = acl

        hrefs = []

        if current_user_acl:
            if userName:
                hrefs.append({
                    'rel': 'self',
                    'href': self.getHref(col_name + '/' + obj_uuid +
                                         '/acls/' + url_escape(userName))
                })
            else:
                hrefs.append({
                    'rel': 'self',
                    'href': self.getHref(col_name + '/' + obj_uuid + '/acls')
                })

        else:
            hrefs.append({
                'rel': 'self',
                'href': self.getHref(col_name + '/' + obj_uuid + '/acls')
            })
        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        hrefs.append({
            'rel': 'owner',
            'href': self.getHref(col_name + '/' + obj_uuid)
        })

        response['hrefs'] = hrefs
        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def put(self):
        self.baseHandler()

        # put - create/update an acl
        # patterns are:
        # PUT /group/<id>/acls/<name> {'read': True, 'write': False }
        # PUT /acls/<name> {'read'... }

        req_uuid = None
        if not self.request.uri.startswith("/acls/"):
            req_uuid = self.getRequestId()
        col_name = self.getRequestCollectionName()
        userName = url_unescape(self.getName())

        if userName is None or len(userName) == 0:
            msg = "Bad Request: username not provided"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        req_userid = None   # this is the userid of the acl we'll be updating
        # self.userid is the userid of the requestor
        if userName == 'default':
            req_userid = 0
        else:
            req_userid = auth.getUserId(userName)

        if req_userid is None:
            msg = "Bad Request: username not found"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        body = None
        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            msg = "JSON Parser Error: " + e.message
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        if 'perm' not in body:
            msg = "Bad Request: 'perm' not found in request body"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        perm = body['perm']
        acl = {}
        acl['userid'] = req_userid
        for key in ('create', 'read', 'update',
                    'delete', 'readACL', 'updateACL'):
            if key in perm:
                acl[key] = 1 if perm[key] else 0
        if len(acl) == 1:
            msg = "Bad Request: no acl permissions found in request body"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        response = {}

        rootUUID = None
        obj_uuid = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                if req_uuid is None:
                    obj_uuid = rootUUID
                else:
                    obj_uuid = req_uuid
                current_user_acl = db.getAcl(obj_uuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(current_user_acl, 'updateACL')
                db.setAcl(obj_uuid, acl)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        hrefs = []

        hrefs.append({
            'rel': 'self',
            'href': self.getHref(col_name + '/' + obj_uuid + '/acls/' +
                                 url_escape(userName))
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        hrefs.append({
            'rel': 'owner',
            'href': self.getHref(col_name + '/' + obj_uuid)
        })

        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)


class TypeHandler(BaseHandler):
    def get(self):
        self.baseHandler()

        if not self.reqUuid:
            msg = "Bad Request: id is not specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        response = {}
        hrefs = []
        rootUUID = None
        item = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getCommittedTypeItemByUuid(self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datatypes/' + self.reqUuid)
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'attributes',
            'href': self.getHref('datatypes/' + self.reqUuid + '/attributes')
        })
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        response['id'] = self.reqUuid
        typeItem = item['type']
        response['type'] = h5json.getTypeResponse(typeItem)
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])
        response['attributeCount'] = item['attributeCount']
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def delete(self):
        self.baseHandler()

        self.isWritable(self.filePath)
        response = {}
        hrefs = []
        rootUUID = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'delete')
                db.deleteObjectByUuid('datatype', self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        hrefs.append({'rel': 'self', 'href': self.getHref('datatypes')})
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})

        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class DatatypeHandler(BaseHandler):
    def get(self):
        self.baseHandler()

        response = {}
        hrefs = []
        rootUUID = None
        item = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getDatasetTypeItemByUuid(self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datasets/' + self.reqUuid + '/type')
        })
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        response['type'] = item['type']

        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class ShapeHandler(BaseHandler):

    def get(self):
        self.baseHandler()

        response = {}
        hrefs = []
        rootUUID = None
        item = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getDatasetItemByUuid(self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        hrefs.append({
            'rel': 'self', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        shape = item['shape']
        response['shape'] = shape
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def put(self):
        self.baseHandler()

        self.isWritable(self.filePath)

        response = {}
        hrefs = []
        rootUUID = None
        body = None
        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            msg = "JSON Parser Error: " + e.message
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        if "shape" not in body:
            msg = "Bad Request: Shape not specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)  # missing shape

        shape = body["shape"]
        if type(shape) == int:
            dim1 = shape
            shape = [dim1]
        elif type(shape) == list or type(shape) == tuple:
            pass  # can use as is
        else:
            msg = "Bad Request: invalid shape argument"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        # validate shape
        for extent in shape:
            if type(extent) != int:
                msg = "Bad Request: invalid shape type (expecting int)"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            if extent < 0:
                msg = "Bad Request: invalid shape (negative extent)"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'update')
                db.resizeDataset(self.reqUuid, shape)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        self.log.info("resize OK")
        # put together the response

        hrefs.append({
            'rel': 'self', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        response['hrefs'] = hrefs

        self.set_status(201)  # resource created
        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class DatasetHandler(BaseHandler):

    def getDatasetNumElements(self, shape_item):

        if shape_item['class'] == 'H5S_SCALAR':
            return 1
        elif shape_item['class'] != 'H5S_SIMPLE':
            return 0

        dims = shape_item['dims']
        rank = len(dims)
        if rank == 0:
            return 1

        count = 1
        for i in range(rank):
            count *= dims[i]
        return count

    def getPreviewQuery(self, shape_item):
        """Helper method - return query options for a "reasonable" size
        data preview selection. Return None if the dataset is small
        enough that a preview is not needed.

        """

        select = "select=["

        dims = shape_item['dims']
        rank = len(dims)

        ncols = dims[rank-1]
        if rank > 1:
            nrows = dims[rank-2]
        else:
            nrows = 1

        # use some rough heuristics to define the selection
        # aim to return no more than 100 elements
        if ncols > 100:
            ncols = 100
        if nrows > 100:
            nrows = 100
        if nrows*ncols > 100:
            if nrows > ncols:
                nrows = 100 // ncols
            else:
                ncols = 100 // nrows

        for i in range(rank):
            if i == rank-1:
                select += "0:" + str(ncols)
            elif i == rank-2:
                select += "0:" + str(nrows) + ","
            else:
                select += "0:1,"
        select += "]"
        return select

    def get(self):
        self.baseHandler()

        response = {}
        hrefs = []
        rootUUID = None
        item = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getDatasetItemByUuid(self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response
        count = self.getDatasetNumElements(item['shape'])

        if count <= 100:
            # small number of values, provide link to entire dataset
            hrefs.append({
                'rel': 'data',
                'href': self.getHref('datasets/' + self.reqUuid + '/value')
            })
        else:
            # large number of values, create preview link
            previewQuery = self.getPreviewQuery(item['shape'])
            hrefs.append({
                'rel': 'preview',
                'href': self.getHref('datasets/' + self.reqUuid + '/value',
                                     query=previewQuery)
            })

        hrefs.append({
            'rel': 'self', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'attributes',
            'href': self.getHref('datasets/' + self.reqUuid + '/attributes')
        })

        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        response['id'] = self.reqUuid
        typeItem = item['type']
        response['type'] = h5json.getTypeResponse(typeItem)
        response['shape'] = item['shape']

        if 'creationProperties' in item:
            response['creationProperties'] = item['creationProperties']
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])
        response['attributeCount'] = item['attributeCount']
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')

        json_rsp = json_encode(response)

        self.write(json_rsp)

    def delete(self):
        self.baseHandler()

        self.isWritable(self.filePath)

        response = {}
        hrefs = []
        rootUUID = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'delete')
                db.deleteObjectByUuid('dataset', self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # write the response
        href = self.request.protocol + '://' + self.request.host + '/'
        hostQuery = ''
        if self.get_query_argument("host", default=None):
            hostQuery = "?host=" + self.get_query_argument("host")
        hrefs.append({'rel': 'self', 'href': href + 'datasets' + hostQuery})
        hrefs.append({
            'rel': 'root', 'href': href + 'groups/' + rootUUID + hostQuery})
        hrefs.append({'rel': 'home', 'href': href + hostQuery})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class ValueHandler(BaseHandler):

    def getSliceQueryParam(self, dim, extent):
        """
        Helper method - return slice for dim based on query params

        Query arg should be in the form: [<dim1>, <dim2>, ... , <dimn>]
         brackets are optional for one dimensional arrays.
         Each dimension, valid formats are:
            single integer: n
            start and end: n:m
            start, end, and stride: n:m:s
        """

        # Get optional query parameters for given dim
        self.log.info("getSliceQueryParam: " + str(dim) + ", " + str(extent))
        query = self.get_query_argument("select", default='ALL')
        if query == 'ALL':
            # just return a slice for the entire dimension
            self.log.info("getSliceQueryParam: return default")
            return slice(0, extent)

        self.log.info("select query value: [" + query + "]")

        if not query.startswith('['):
            msg = "Bad Request: selection query missing start bracket"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        if not query.endswith(']'):
            msg = "Bad Request: selection query missing end bracket"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        # now strip out brackets
        query = query[1:-1]

        query_array = query.split(',')
        if dim > len(query_array):
            msg = "Not enough dimensions supplied to query argument"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        dim_query = query_array[dim].strip()
        start = 0
        stop = extent
        step = 1
        if dim_query.find(':') < 0:
            # just a number - return start = stop for this value
            try:
                start = int(dim_query)
            except ValueError:
                msg = "Bad Request: invalid selection parameter " +\
                    "(can't convert to int) for dimension: " + str(dim)
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            stop = start
        elif dim_query == ':':
            # select everything
            pass
        else:
            fields = dim_query.split(":")
            if len(fields) > 3:
                msg = "Bad Request: Too many ':' seperators for dimension: " \
                    + str(dim)
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            try:
                if fields[0]:
                    start = int(fields[0])
                if fields[1]:
                    stop = int(fields[1])
                if len(fields) > 2 and fields[2]:
                    step = int(fields[2])
            except ValueError:
                msg = "Bad Request: invalid selection parameter (can't " + \
                    "convert to int) for dimension: " + str(dim)
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

        if start < 0 or start > extent:
            msg = "Bad Request: Invalid selection start parameter for" + \
                "dimension: " + str(dim)
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        if stop > extent:
            msg = "Bad Request: Invalid selection stop parameter for " + \
                "dimension: " + str(dim)
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        if step <= 0:
            msg = "Bad Request: invalid selection step parameter for " + \
                "dimension: " + str(dim)
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        s = slice(start, stop, step)
        self.log.info(
            "dim query[" + str(dim) + "] returning: start: " +
            str(start) + " stop: " + str(stop) + " step: " + str(step))
        return s

    def getHyperslabSelection(self, dsetshape, start, stop, step):
        """
        Get slices given lists of start, stop, step values
        """
        rank = len(dsetshape)
        if start:
            if type(start) is not list:
                start = [start]
            if len(start) != rank:
                msg = "Bad Request: start array length not equal to " + \
                    "dataset rank"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            for dim in range(rank):
                if start[dim] < 0 or start[dim] >= dsetshape[dim]:
                    msg = "Bad Request: start index invalid for dim: " + \
                        str(dim)
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
        else:
            start = []
            for dim in range(rank):
                start.append(0)

        if stop:
            if type(stop) is not list:
                stop = [stop]
            if len(stop) != rank:
                msg = "Bad Request: stop array length not equal to dataset" + \
                    "rank"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            for dim in range(rank):
                if stop[dim] <= start[dim] or stop[dim] > dsetshape[dim]:
                    msg = "Bad Request: stop index invalid for dim: " + \
                        str(dim)
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
        else:
            stop = []
            for dim in range(rank):
                stop.append(dsetshape[dim])

        if step:
            if type(step) is not list:
                step = [step]
            if len(step) != rank:
                msg = "Bad Request: step array length not equal to dataset" + \
                    "rank"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            for dim in range(rank):
                if step[dim] <= 0 or step[dim] > dsetshape[dim]:
                    msg = "Bad Request: step index invalid for dim: " + \
                        str(dim)
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
        else:
            step = []
            for dim in range(rank):
                step.append(1)

        slices = []
        for dim in range(rank):
            try:
                s = slice(int(start[dim]), int(stop[dim]), int(step[dim]))
            except ValueError:
                msg = "Bad Request: invalid start/stop/step value"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            slices.append(s)
        return tuple(slices)

    def get(self):
        self.baseHandler()

        request_content_type = self.getAcceptType()
        response_content_type = "json"
        self.log.info("contenttype:" + request_content_type)

        response = {}
        hrefs = []
        rootUUID = None
        item = None
        item_shape = None
        rank = None
        item_type = None
        values = None
        indexes = None
        slices = []
        query_selection = self.get_query_argument("query", default=None)
        limit = self.get_query_argument("Limit", default=None)
        if limit:
            try:
                limit = int(limit)  # convert to int
            except ValueError as e:
                msg = "invalid Limit: " + e.message
                self.log.info(msg)
                raise HTTPError(400, msg)

        if query_selection:
            self.log.info("query: " + query_selection)

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getDatasetItemByUuid(self.reqUuid)
                item_type = item['type']

                if item_type['class'] == 'H5T_OPAQUE':
                    # TODO - support for returning OPAQUE data...
                    msg = "Not Implemented: GET OPAQUE data not supported"
                    self.log.info(msg)
                    raise HTTPError(501, reason=msg)  # Not implemented
                elif item_type['class'] != 'H5T_COMPOUND' and query_selection:
                    msg = "Bad Request: query selection is only supported " + \
                        "for compound types"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)

                item_shape = item['shape']
                if item_shape['class'] == 'H5S_NULL':
                    pass   # don't return a value
                elif item_shape['class'] == 'H5S_SCALAR':
                    if query_selection:
                        msg = "Bad Request: query selection not valid with" + \
                            " scalar dataset"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)
                    values = db.getDatasetValuesByUuid(self.reqUuid, Ellipsis)
                    if isinstance(values, numpy.ndarray):
                        values = values.tolist()
                elif item_shape['class'] == 'H5S_SIMPLE':
                    dims = item_shape['dims']
                    rank = len(dims)
                    if query_selection and rank != 1:
                        msg = "Bad Request: query selection is only " + \
                            "supported for "
                        msg += "one dimensional datasets"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)
                    nelements = 1
                    for dim in range(rank):
                        dim_slice = self.getSliceQueryParam(dim, dims[dim])
                        nelements *= (dim_slice.stop - dim_slice.start)
                        slices.append(dim_slice)
                    if query_selection:
                        start = slices[0].start
                        stop = slices[0].stop
                        step = slices[0].step
                        (indexes, values) = db.doDatasetQueryByUuid(
                            self.reqUuid, query_selection, start=start,
                            stop=stop, step=step, limit=limit)
                    else:
                        if request_content_type == "binary":
                            self.log.info("nelements:" + str(nelements))
                            itemSize = h5json.getItemSize(item_type)
                            if itemSize != "H5T_VARIABLE" and nelements > 1:
                                response_content_type = "binary"

                        self.log.info("response_content_type: " +
                                      response_content_type)
                        values = db.getDatasetValuesByUuid(
                            self.reqUuid, tuple(slices), response_content_type)

                        # ### Jason mucking about... ### #
                        item_alias = item['alias']
                        self.log.info('item_alias: ' + str(item_alias))
                        self.log.info('item: ' + str(item))
                        self.log.info('slices: ' + str(slices))
                        self.log.info('dims: ' + str(dims))
                        self.log.info('filePath: ' + self.filePath)
                        values = largeImages.decimate_if_necessary(
                            values, slices, self.filePath, True, True)
                        ##################################

                else:
                    msg = "Internal Server Error: unexpected shape class: " + \
                        item_shape['class']
                    self.log.error(msg)
                    raise HTTPError(500, reason=msg)

                rootUUID = db.getUUIDByPath('/')
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        if response_content_type == "binary":
            # binary transfer, just write the bytes and return
            self.log.info("writing binary stream")
            self.set_header('Content-Type', 'application/octet-stream')
            self.write(values)
            return

        if request_content_type == "binary":
            # unable to return binary data
            self.log.info("requested binary response, but returning JSON " +
                          "instead")

        selfQuery = []
        if self.get_query_argument("select", default=''):
            selfQuery.append('select=' + self.get_query_argument("select"))
        if self.get_query_argument("query", default=''):
            selfQuery.append('query=' + self.get_query_argument(
                "select", default=''))

        if values is not None:
            response['value'] = values
        else:
            response['value'] = None

        if indexes is not None:
            response['index'] = indexes

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datasets/' + self.reqUuid + '/value',
                                 query=selfQuery)
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({
            'rel': 'home', 'href': self.getHref('')})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def post(self):
        self.baseHandler()

        body = None
        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            msg = "JSON Parser Error: " + e.message
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        if "points" not in body:
            msg = "Bad Request: value post request without points in body"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        points = body['points']
        if type(points) != list:
            msg = "Bad Request: expecting list of points"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        response = {}
        hrefs = []
        rootUUID = None
        item = None
        values = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getDatasetItemByUuid(self.reqUuid)
                shape = item['shape']
                if shape['class'] == 'H5S_SCALAR':
                    msg = "Bad Request: point selection is not supported " + \
                        "on scalar datasets"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
                if shape['class'] == 'H5S_NULL':
                    msg = "Bad Request: point selection is not supported " + \
                        "on Null Space datasets"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)

                rank = len(shape['dims'])

                for point in points:
                    if rank == 1 and type(point) != int:
                        msg = "Bad Request: elements of points should be " + \
                            "int type for datasets of rank 1"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)
                    elif rank > 1 and type(point) != list:
                        msg = "Bad Request: elements of points should be " + \
                            "list type for datasets of rank >1"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)
                        if len(point) != rank:
                            msg = "Bad Request: one or more points have a " + \
                                "missing coordinate value"
                            self.log.info(msg)
                            raise HTTPError(400, reason=msg)

                values = db.getDatasetPointSelectionByUuid(self.reqUuid,
                                                           points)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        response['value'] = values

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datasets/' + self.reqUuid + '/value')
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'owner', 'href': self.getHref('datasets/' + self.reqUuid)})
        hrefs.append({'rel': 'home',  'href': self.getHref('')})

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def put(self):
        self.baseHandler()

        points = None
        start = None
        stop = None
        step = None
        body = None
        format = "json"
        data = None

        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            try:
                msg = "JSON Parser Error: " + e.message
            except AttributeError:
                msg = "JSON Parser Error"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        if "value" in body:
            data = body["value"]
            format = "json"
        elif "value_base64" in body:
            base64_data = body["value_base64"]
            base64_data = base64_data.encode("ascii")
            data = base64.b64decode(base64_data)
            format = "binary"

        else:
            msg = "Bad Request: Value not specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)  # missing data

        if "points" in body:
            points = body['points']
            if type(points) != list:
                msg = "Bad Request: expecting list of points"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            if 'start' in body or 'stop' in body or 'step' in body:
                msg = "Bad Request: can use hyperslab selection and " + \
                    "points selection in one request"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            if len(points) > len(data):
                msg = "Bad Request: more points provided than values"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        else:
            # hyperslab selection
            if 'start' in body:
                start = body['start']
            if 'stop' in body:
                stop = body['stop']
            if 'step' in body:
                step = body['step']

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                # rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'update')
                item = db.getDatasetItemByUuid(self.reqUuid)
                item_type = item['type']

                dims = None
                if 'shape' not in item:
                    msg = "Unexpected error, shape information not found"
                    self.log.info(msg)
                    raise HTTPError(500, reason=msg)
                datashape = item['shape']
                if datashape['class'] == 'H5S_NULL':
                    msg = "Bad Request: PUT value can't be used with Null " + \
                        "Space datasets"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)  # missing data

                if format == "binary":
                    item_size = h5json.getItemSize(item_type)
                    if item_size == "H5T_VARIABLE":
                        msg = "binary data cannot be used with variable " + \
                            "length types"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)  # need to use json

                if datashape['class'] == 'H5S_SIMPLE':
                    dims = datashape['dims']
                elif datashape['class'] == 'H5S_SCALAR':
                    if start is not None or stop is not None or \
                            step is not None:
                        msg = "Bad Request: start/stop/step option can't " + \
                            "be used with Scalar Space datasets"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)  # missing data
                    elif points:
                        msg = "Bad Request: Point selection can't be used " + \
                            "with scalar datasets"
                        self.log.info(msg)
                        raise HTTPError(400, reason=msg)  # missing data

                if points is not None:
                    # write point selection
                    db.setDatasetValuesByPointSelection(
                        self.reqUuid, data, points, format=format)

                else:
                    slices = None
                    if dims is not None:
                        slices = self.getHyperslabSelection(
                            dims, start, stop, step)
                    # todo - check that the types are compatible
                    db.setDatasetValuesByUuid(
                        self.reqUuid, data, slices, format=format)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        self.log.info("value put succeeded")


class AttributeHandler(BaseHandler):

    # convert embedded list (list of lists) to tuples
    def convertToTuple(self, data):
        if type(data) == list or type(data) == tuple:
            sublist = []
            for e in data:
                sublist.append(self.convertToTuple(e))
            return tuple(sublist)
        else:
            return data

    def getRequestName(self):
        # request is in the form
        # /(datasets|groups|datatypes)/<id>/attributes(/<name>), return <name>
        # return None if the uri doesn't end with ".../<name>"
        uri = self.request.uri
        name = None
        npos = uri.rfind('/attributes')
        if npos <= 0:
            msg = "Bad Request: URI is invalid"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        uri = uri[npos+len('/attributes'):]
        if uri[0:1] == '/':
            uri = uri[1:]
            if len(uri) > 0:
                # strip off any query param
                npos = uri.rfind('?')
                if npos > 0:
                    uri = uri[:npos]
                name = url_unescape(uri)  # todo: handle possible query string?
                self.log.info('got name: [' + name + ']')

        return name

    def getRequestCollectionName(self):
        # request is in the form
        # /(datasets|groups|datatypes)/<id>/attributes(/<name>), return
        # datasets | groups | datatypes
        uri = self.request.uri

        npos = uri.find('/')
        if npos < 0:
            self.log.info("bad uri")
            raise HTTPError(400)
        uri = uri[(npos+1):]
        npos = uri.find('/')  # second '/'
        col_name = uri[:npos]

        self.log.info('got collection name: [' + col_name + ']')
        if col_name not in ('datasets', 'groups', 'datatypes'):
            msg = "Internal Server Error: collection name unexpected"
            self.log.error(msg)
            # shouldn't get routed here in this case
            raise HTTPError(500, reason=msg)

        return col_name

    def get(self):
        self.baseHandler()

        col_name = self.getRequestCollectionName()
        attr_name = self.getRequestName()

        response = {}
        hrefs = []
        rootUUID = None
        items = []
        # Get optional query parameters
        limit = self.get_query_argument("Limit", 0)
        if type(limit) is not int:
            try:
                limit = int(limit)
            except ValueError:
                self.log.info("expected int type for limit")
                raise HTTPError(400)
        marker = self.get_query_argument("Marker", None)

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                if attr_name is not None:
                    item = db.getAttributeItem(col_name, self.reqUuid,
                                               attr_name)
                    items.append(item)
                else:
                    # get all attributes (but without data)
                    items = db.getAttributeItems(col_name, self.reqUuid,
                                                 marker, limit)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response
        owner_uri = col_name + '/' + self.reqUuid
        self_uri = owner_uri + '/attributes'
        if attr_name is not None:
            self_uri += '/' + url_escape(attr_name)

        # hostQuery = ''
        # if self.get_query_argument("host", default=None):
        #     hostQuery = "?host=" + self.get_query_argument("host")

        responseItems = []
        for item in items:
            responseItem = {}
            responseItem['name'] = item['name']
            typeItem = item['type']
            responseItem['type'] = h5json.getTypeResponse(typeItem)
            responseItem['shape'] = item['shape']
            responseItem['created'] = unixTimeToUTC(item['ctime'])
            responseItem['lastModified'] = unixTimeToUTC(item['mtime'])
            if not attr_name or typeItem['class'] == 'H5T_OPAQUE':
                pass  # TODO - send data for H5T_OPAQUE's
            elif 'value' in item:
                responseItem['value'] = item['value']
            else:
                responseItem['value'] = None
            if attr_name is None:
                # add an href to the attribute
                responseItem['href'] = self.getHref(self_uri + '/' +
                                                    url_escape(item['name']))

            responseItems.append(responseItem)

        hrefs.append({'rel': 'self', 'href': self.getHref(self_uri)})
        hrefs.append({'rel': 'owner', 'href': self.getHref(owner_uri)})
        hrefs.append({'rel': 'root', 'href': self.getHref('/groups/' +
                     rootUUID)})
        hrefs.append({'rel': 'home', 'href': self.getHref('')})

        if attr_name is None:
            # specific attribute response
            response['attributes'] = responseItems
        else:
            if len(responseItems) == 0:
                # should have raised exception earlier
                self.log.error("attribute not found: " + attr_name)
                raise HTTPError(404)
            responseItem = responseItems[0]
            for k in responseItem:
                response[k] = responseItem[k]

        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def put(self):
        self.baseHandler()

        col_name = self.getRequestCollectionName()
        attr_name = self.getRequestName()
        if attr_name is None:
            msg = "Bad Request: attribute name not supplied"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        body = None
        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            msg = "JSON Parser Error"
            try:
                msg += ": " + e.message
            except AttributeError:
                # no message property
                pass

            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        if "type" not in body:
            self.log.info("Type not supplied")
            raise HTTPError(400)  # missing type

        dims = ()  # default as empty tuple (will create a scalar attribute)
        if "shape" in body:
            shape = body["shape"]
            if type(shape) == int:
                dims = [shape]
            elif type(shape) == list or type(shape) == tuple:
                dims = shape  # can use as is
            elif type(shape) in (str, unicode) and shape == 'H5S_NULL':
                dims = None
            else:
                msg = "Bad Request: shape is invalid!"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        datatype = body["type"]

        # validate shape
        if dims:
            for extent in dims:
                if type(extent) != int:
                    msg = "Bad Request: invalid shape type"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
                if extent < 0:
                    msg = "Bad Request: invalid shape (negative extent)"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)

        # convert list values to tuples (otherwise h5py is not happy)
        data = None

        if dims is not None:
            if "value" not in body:
                msg = "Bad Request: value not specified"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)  # missing value
            value = body["value"]

            data = self.convertToTuple(value)

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'create')
                db.createAttribute(
                    col_name, self.reqUuid, attr_name, dims, datatype, data)
                rootUUID = db.getUUIDByPath('/')

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        response = {}

        # got everything we need, put together the response
        root_href = self.getHref('groups/' + rootUUID)
        owner_href = self.getHref(col_name + '/' + self.reqUuid)
        self_href = owner_href + '/attributes'
        if attr_name is not None:
            self_href = self.getHref(col_name + '/' + self.reqUuid + '/' +
                                     attr_name)
        else:
            self_href = self.getHref(col_name + '/' + self.reqUuid)

        hrefs = []
        hrefs.append({'rel': 'self',   'href': self_href})
        hrefs.append({'rel': 'owner',  'href': owner_href})
        hrefs.append({'rel': 'root',   'href': root_href})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)  # resource created

    def delete(self):
        self.baseHandler()

        col_name = self.getRequestCollectionName()
        attr_name = self.getRequestName()
        if attr_name is None:
            msg = "Bad Request: attribute name not specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)
        self.filePath = self.getFilePath(self.domain)
        self.isWritable(self.filePath)

        response = {}
        hrefs = []
        rootUUID = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'delete')
                db.deleteAttribute(col_name, self.reqUuid, attr_name)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        root_href = self.getHref('groups/' + rootUUID)
        owner_href = self.getHref(col_name + '/' + self.reqUuid)
        self_href = self.getHref(col_name + '/' + self.reqUuid + '/attributes')
        home_href = self.getHref('')

        hrefs.append({'rel': 'self', 'href': self_href})
        hrefs.append({'rel': 'owner', 'href': owner_href})
        hrefs.append({'rel': 'root', 'href': root_href})
        hrefs.append({'rel': 'home', 'href': home_href})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

        self.log.info("Attribute delete succeeded")


class GroupHandler(BaseHandler):

    def get(self):
        self.baseHandler()

        response = {}

        hrefs = []
        rootUUID = None
        item = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                item = db.getGroupItemByUuid(self.reqUuid)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # got everything we need, put together the response

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('groups/' + self.reqUuid)
        })
        hrefs.append({
            'rel': 'links',
            'href': self.getHref('groups/' + self.reqUuid + '/links')
        })
        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        hrefs.append({
            'rel': 'home',
            'href': self.getHref('')
        })
        hrefs.append({
            'rel': 'attributes',
            'href': self.getHref('groups/' + self.reqUuid + '/attributes')
        })
        response['id'] = self.reqUuid
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])
        response['attributeCount'] = item['attributeCount']
        response['linkCount'] = item['linkCount']
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def delete(self):
        self.baseHandler()

        self.isWritable(self.filePath)
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(self.reqUuid, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'delete')
                db.deleteObjectByUuid('group', self.reqUuid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        response = {}
        hrefs = []

        # write the response

        hrefs.append({'rel': 'self', 'href': self.getHref('groups')})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))


class GroupCollectionHandler(BaseHandler):

    def get(self):
        self.baseHandler()

        rootUUID = None

        # Get optional query parameters
        limit = self.get_query_argument("Limit", 0)
        if type(limit) is not int:
            try:
                limit = int(limit)
            except ValueError:
                self.log.info("expected int type for limit")
                raise HTTPError(400)
        marker = self.get_query_argument("Marker", None)

        response = {}

        items = None
        hrefs = []

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(rootUUID, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                items = db.getCollection("groups", marker, limit)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # write the response
        response['groups'] = items

        hrefs.append({
            'rel': 'self', 'href': self.getHref('groups')})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'home', 'href': self.getHref('')})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def post(self):
        self.baseHandler()

        if self.request.uri != '/groups':
            msg = "Method Not Allowed: bad group post request: " + \
                self.request.uri
            self.log.info(msg)
            raise HTTPError(405, reason=msg)  # Method not allowed

        parent_group_uuid = None
        link_name = None

        body = {}
        if self.request.body:
            try:
                body = json_decode(self.request.body)
            except ValueError as e:
                msg = "JSON Parser Error: " + e.message
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

        if "link" in body:
            link_options = body["link"]
            if "id" not in link_options or "name" not in link_options:
                msg = "Bad Request: missing link parameter"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            parent_group_uuid = link_options["id"]
            link_name = link_options["name"]
            self.log.info("add link to: " + parent_group_uuid + " with name: "
                          + link_name)

        self.isWritable(self.filePath)

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                current_user_acl = db.getAcl(rootUUID, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(current_user_acl, 'create')
                grpUUID = db.createGroup()
                item = db.getGroupItemByUuid(grpUUID)

                # if link info is provided, link the new group
                if parent_group_uuid:
                    # link the new dataset
                    db.linkObject(parent_group_uuid, grpUUID, link_name)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        href = self.request.protocol + '://' + self.domain
        self.set_header('Location', href + '/groups/' + grpUUID)
        self.set_header('Content-Location', href + '/groups/' + grpUUID)

        # got everything we need, put together the response
        response = {}
        hrefs = []

        hrefs.append({
            'rel': 'self', 'href': self.getHref('groups/' + grpUUID)})
        hrefs.append({
            'rel': 'links',
            'href': self.getHref('groups/' + grpUUID + '/links')
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'home', 'href': self.getHref('')})
        hrefs.append({
            'rel': 'attributes',
            'href': self.getHref('groups/' + grpUUID + '/attributes')
        })
        response['id'] = grpUUID
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])
        response['attributeCount'] = item['attributeCount']
        response['linkCount'] = item['linkCount']
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)  # resource created


class DatasetCollectionHandler(BaseHandler):

    def get(self):
        self.baseHandler()

        # Get optional query parameters
        limit = self.get_query_argument("Limit", 0)
        if type(limit) is not int:
            try:
                limit = int(limit)
            except ValueError:
                msg = "Bad Request: expected int type for limit"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        marker = self.get_query_argument("Marker", None)

        response = {}
        hrefs = []
        rootUUID = None

        items = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(rootUUID, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                items = db.getCollection("datasets", marker, limit)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # write the response
        response['datasets'] = items

        hrefs.append({'rel': 'self', 'href': self.getHref('datasets')})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def post(self):
        self.baseHandler()

        if self.request.uri != '/datasets':
            msg = "Method not Allowed: invalid datasets post request"
            self.log.info(msg)
            raise HTTPError(405, reason=msg)  # Method not allowed

        self.isWritable(self.filePath)
        dims = None
        group_uuid = None
        link_name = None

        body = {}
        if self.request.body:
            try:
                body = json_decode(self.request.body)
            except ValueError as e:
                msg = "JSON Parser Error: " + e.message
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

        if "type" not in body:
            msg = "Bad Request: Type not specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)  # missing type

        if "shape" in body:
            shape = body["shape"]
            if type(shape) == int:
                dims = [shape]
            elif type(shape) == list or type(shape) == tuple:
                dims = shape  # can use as is
            elif type(shape) in (str, unicode) and shape == 'H5S_NULL':
                dims = None
            else:
                msg = "Bad Request: shape is invalid"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        else:
            dims = ()  # empty tuple

        if "link" in body:
            link_options = body["link"]
            if "id" not in link_options or "name" not in link_options:
                msg = "Bad Request: No 'name' or 'id' not specified"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

            group_uuid = link_options["id"]
            link_name = link_options["name"]
            self.log.info("add link to: " + group_uuid + " with name: " +
                          link_name)

        datatype = body["type"]

        maxdims = None
        if "maxdims" in body:
            maxdims = body["maxdims"]
            if type(maxdims) == int:
                dim1 = maxdims
                maxdims = [dim1]
            elif type(maxdims) == list or type(maxdims) == tuple:
                pass  # can use as is
            else:
                msg = "Bad Request: maxdims is invalid"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

        # validate shape
        if dims:
            for extent in dims:
                if type(extent) != int:
                    msg = "Bad Request: Invalid shape type"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
                if extent < 0:
                    msg = "Bad Request: shape dimension is negative"
                    self.log.info("msg")
                    raise HTTPError(400, reason=msg)

        if maxdims:
            if dims is None:
                # can't use maxdims with null_space dataset
                msg = "Bad Request: maxdims not valid for H5S_NULL dataspace"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)

            if len(maxdims) != len(dims):
                msg = "Bad Request: maxdims array length must equal shape " + \
                    "array length"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            for i in range(len(dims)):
                maxextent = maxdims[i]
                if maxextent != 0 and maxextent < dims[i]:
                    msg = "Bad Request: maxdims extent can't be smaller " + \
                        "than shape extent"
                    self.log.info(msg)
                    raise HTTPError(400, reason=msg)
                if maxextent == 0:
                    maxdims[i] = None  # this indicates unlimited

        creationProps = None
        if "creationProperties" in body:
            creationProps = body["creationProperties"]
        item = None
        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(rootUUID, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'create')
                # verify the link perm as well
                if group_uuid and group_uuid != rootUUID:
                    acl = db.getAcl(group_uuid, self.userid)

                    # throws exception is unauthorized
                    self.verifyAcl(acl, 'create')

                item = db.createDataset(datatype, dims, maxdims,
                                        creation_props=creationProps)
                if group_uuid:
                    # link the new dataset
                    db.linkObject(group_uuid, item['id'], link_name)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        response = {}

        # got everything we need, put together the response
        hrefs = []

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datasets/' + item['id'])
        })
        hrefs.append({
            'rel': 'root',
            'href': self.getHref('groups/' + rootUUID)
        })
        hrefs.append({
            'rel': 'attributes',
            'href': self.getHref('datasets/' + item['id'] + '/attributes')
        })
        hrefs.append({
            'rel': 'value',
            'href': self.getHref('datasets/' + item['id'] + '/value')})
        response['id'] = item['id']
        response['attributeCount'] = item['attributeCount']
        response['hrefs'] = hrefs
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)  # resource created


class TypeCollectionHandler(BaseHandler):
    def get(self):
        self.baseHandler()

        # Get optional query parameters
        limit = self.get_query_argument("Limit", 0)
        if type(limit) is not int:
            try:
                limit = int(limit)
            except ValueError:
                msg = "Bad Request: expected int type for Limit"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
        marker = self.get_query_argument("Marker", None)

        response = {}
        hrefs = []
        rootUUID = None

        items = None
        try:
            with Hdf5db(self.filePath) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(rootUUID, self.userid)
                self.verifyAcl(acl, 'read')  # throws exception is unauthorized
                items = db.getCollection("datatypes", marker, limit)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        # write the response
        response['datatypes'] = items

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datatypes')
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({'rel': 'home', 'href': self.getHref('')})
        response['hrefs'] = hrefs

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def post(self):
        self.baseHandler()

        if self.request.uri != '/datatypes':
            msg = "Method not Allowed: invalid URI"
            self.log.info(msg)
            raise HTTPError(405, reason=msg)  # Method not allowed

        self.isWritable(self.filePath)

        body = None
        try:
            body = json_decode(self.request.body)
        except ValueError as e:
            msg = "JSON Parser Error: " + e.message
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        parent_group_uuid = None
        link_name = None

        if "type" not in body:
            msg = "Type not specified"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)  # missing type

        if "link" in body:
            link_options = body["link"]
            if "id" not in link_options or "name" not in link_options:
                msg = "Bad Request: missing link parameter"
                self.log.info(msg)
                raise HTTPError(400, reason=msg)
            parent_group_uuid = link_options["id"]
            link_name = link_options["name"]
            self.log.info(
                "add link to: " + parent_group_uuid + " with name: " +
                link_name)

        datatype = body["type"]

        item = None
        rootUUID = None

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(rootUUID, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'create')
                item = db.createCommittedType(datatype)
                # if link info is provided, link the new group
                if parent_group_uuid:
                    # link the new dataset
                    db.linkObject(parent_group_uuid, item['id'], link_name)

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        response = {}

        # got everything we need, put together the response
        hrefs = []

        hrefs.append({
            'rel': 'self',
            'href': self.getHref('datatypes/' + item['id'])
        })
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})
        hrefs.append({
            'rel': 'attributes',
            'href': self.getHref('datatypes/' + item['id'] + '/attributes')
        })
        response['id'] = item['id']
        response['attributeCount'] = 0
        response['hrefs'] = hrefs
        response['created'] = unixTimeToUTC(item['ctime'])
        response['lastModified'] = unixTimeToUTC(item['mtime'])

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)  # resource created


class RootHandler(BaseHandler):

    def getRootResponse(self, filePath):
        acl = None
        # used by GET / and PUT /

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:

                rootUUID = db.getUUIDByPath('/')

                self.log.info("rootUUID: " + str(rootUUID))
                self.log.info("self.filePath: " + str(self.filePath))
                self.log.info("self.userid: " + str(self.userid))

                acl = db.getAcl(rootUUID, self.userid)

                self.log.info("acl: " + str(acl))

        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + str(e.strerror))
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        self.verifyAcl(acl, 'read')  # throws exception is unauthorized

        # generate response
        hrefs = []

        hrefs.append({
            'rel': 'self', 'href': self.getHref('')})
        hrefs.append({
            'rel': 'database', 'href': self.getHref('datasets')})
        hrefs.append({'rel': 'groupbase', 'href': self.getHref('groups')})
        hrefs.append({
            'rel': 'typebase', 'href': self.getHref('datatypes')})
        hrefs.append({
            'rel': 'root', 'href': self.getHref('groups/' + rootUUID)})

        response = {}
        response['created'] = unixTimeToUTC(op.getctime(filePath))
        response['lastModified'] = unixTimeToUTC(op.getmtime(filePath))
        response['root'] = rootUUID
        response['hrefs'] = hrefs

        return response

    def get(self):

        self.log.info('RootHandler.get')

        self.baseHandler()
        """
        self.log.info("header keys...")
        for k in self.request.headers.keys():
            self.log.info("header[" + k + "]: " + self.request.headers[k])
        self.log.info('remote_ip: ' + self.request.remote_ip)
        """
        try:
            response = self.getRootResponse(self.filePath)
        except HTTPError as e:
            if e.status_code == 401:
                # no user provied, just return 401 response
                return
            raise e  # re-throw the exception

        # root_uuid = response['root']

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))

    def put(self):
        self.baseHandler(checkExists=False)

        self.log.info("filePath: " + self.filePath)

        if self.filePath is not None and fileUtil.isFile(self.filePath):
            # the file already exists
            msg = "Conflict: resource exists: " + self.filePath
            self.log.info(msg)
            # Conflict - is this the correct code?
            raise HTTPError(409, reason=msg)

        if self.filePath is not None and self.isTocFilePath(self.filePath):
            msg = "Forbidden: invalid resource"
            self.log.info(msg)
            raise HTTPError(403, reason=msg)  # Forbidden - TOC file

        if self.filePath is None:
            msg = "domain not valid"
            self.log.info(msg)
            raise HTTPError(400, reason=msg)

        self.log.info("FilePath: " + self.filePath)
        # create directories as needed
        fileUtil.makeDirs(op.dirname(self.filePath))
        self.log.info("creating file: [" + self.filePath + "]")

        try:
            Hdf5db.createHDF5File(self.filePath)
        except IOError as e:
            self.log.info(
                "IOError creating new HDF5 file: " + str(e.errno) + " " +
                e.strerror)
            raise HTTPError(
                500, "Unexpected error: unable to create collection")

        response = self.getRootResponse(self.filePath)

        try:
            tocUtil.addTocEntry(self.domain, self.filePath, userid=self.userid)
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        self.set_header('Content-Type', 'application/json')
        self.write(json_encode(response))
        self.set_status(201)  # resource created

    def delete(self):
        self.baseHandler()

        self.isWritable(self.filePath)

        if not op.isfile(self.filePath):
            # file not there
            msg = "Not found: resource does not exist"
            self.log.info(msg)
            raise HTTPError(404, reason=msg)  # Not found

        # don't use os.access since it will always return OK if uid is root
        if not os.stat(self.filePath).st_mode & 0o200:
            # file is read-only
            msg = "Forbidden: Resource is read-only"
            self.log.info(msg)
            raise HTTPError(403, reason=msg)  # Forbidden

        if self.isTocFilePath(self.filePath):
            msg = "Forbidden: Resource is read-only"
            self.log.info(msg)
            raise HTTPError(403, reason=msg)  # Forbidden - TOC file

        try:
            with Hdf5db(self.filePath, app_logger=self.log) as db:
                rootUUID = db.getUUIDByPath('/')
                acl = db.getAcl(rootUUID, self.userid)
                print("verify delete, ", acl, self.userid)

                # throws exception is unauthorized
                self.verifyAcl(acl, 'delete')
        except IOError as e:
            self.log.info("IOError: " + str(e.errno) + " " + e.strerror)
            status = errNoToHttpStatus(e.errno)
            raise HTTPError(status, reason=e.strerror)

        try:
            tocUtil.removeTocEntry(self.domain, self.filePath,
                                   userid=self.userid)
        except IOError as ioe:
            # This exception may happen if the file has been imported directly
            # after toc creation
            self.log.warn("IOError removing toc entry")

        try:
            os.remove(self.filePath)
        except IOError as ioe:
            self.log.info(
                "IOError deleting HDF5 file: " + str(ioe.errno) + " " +
                ioe.strerror)
            raise HTTPError(
                500, "Unexpected error: unable to delete collection")


class InfoHandler(RequestHandler):

    def get(self):
        log = logging.getLogger("h5serv")
        log.info('InfoHandler.get ' + self.request.host)
        log.info('remote_ip: ' + self.request.remote_ip)

        greeting = "Welcome to h5serv!"
        about = "h5serv is a webservice for HDF5 data"
        doc_href = "http://h5serv.readthedocs.org"
        h5serv_version = "0.2"
        response = Hdf5db.getVersionInfo()
        response['name'] = "h5serv"
        response['greeting'] = greeting
        response['about'] = about
        response['documentation'] = doc_href
        response['h5serv_version'] = h5serv_version

        accept_type = ''
        if 'accept' in self.request.headers:
            accept = self.request.headers['accept']
            # just extract the first type and not worry about q values for
            # now...
            accept_values = accept.split(',')
            accept_types = accept_values[0].split(';')
            accept_type = accept_types[0]
            # print 'accept_type:', accept_type
        if accept_type == 'text/html':
            self.set_header('Content-Type', 'text/html')
            htmlText = "<html><body><h1>" + response['greeting'] + "</h1>"
            htmlText += "<h2>" + response['about'] + "</h2>"
            htmlText += "<h2>Documentation: <a href=" + \
                response['documentation'] + \
                "> h5serv documentation </a></h2>"
            htmlText += "<h2>server version: " + \
                response['h5serv_version'] + "</h2>"
            htmlText += "<h2>h5py version: " + \
                response['h5py_version'] + "</h2>"
            htmlText += "<h2>hdf5 version: " + \
                response['hdf5_version'] + "</h2>"
            htmlText += "</body></html>"
            self.write(htmlText)
        else:
            self.set_header('Content-Type', 'application/json')
            self.write(json_encode(response))


class CasClientMixin(object):
    @property
    def cas_server_url(self):
        return 'https://cas.maxiv.lu.se/cas/'

    @property
    def service_url(self):
        return self.request.full_url()

    def get_next_url(self, default='/'):
        return self.get_argument('next', default)

    def get_login_url(self):
        params = {'service': self.service_url}
        self.log = logging.getLogger("h5serv")
        self.log.info('self.service_url: ' + str(self.service_url))
        return '%s/login?%s' % (self.cas_server_url, urllib.urlencode(params))

    def get_logout_url(self, next_page=None):
        url = '%s/logout' % self.cas_server_url
        next_page = next_page or self.get_next_url()
        if next_page:
            params = {
                'url': "%s://%s%s" % (
                    self.request.protocol, self.request.host,
                    self.request.uri,
                ),
            }

            url += '?' + urllib.urlencode(params)

        return url

    def verify_cas(self, ticket, service):
        """
        Verifies CAS 3.0+ XML-based authentication ticket and returns extended
        attributes.  Returns username on success and None on failure.
        """

        self.log = logging.getLogger("h5serv")
        self.log.info('CasClientMixin.verify_cas() called')

        try:
            from xml.etree import ElementTree
        except ImportError:
            from elementtree import ElementTree

        self.log.info('service: ' + str(service))
        # params = {'ticket': ticket, 'service': service}
        params = {'ticket': ticket, 'service':
                  'https://w-jasbru-pc-0.maxiv.lu.se/hdf5-web-gui/html/'}
        #           'https://w-jasbru-pc-0:6050/login'}
        self.log.info('params: ' + str(params))
        url = '%s/p3/serviceValidate?%s' % (self.cas_server_url,
                                            urllib.urlencode(params))
        page = urllib.urlopen(url)

        self.log.info('url sent to CAS server: ')
        self.log.info(url)

        try:
            user = None
            attributes = {}

            response = page.read()
            self.log.info('response: ' + str(response))

            tree = ElementTree.fromstring(response)
            self.log.info('tree: ' + str(tree))

            if tree[0].tag.endswith('authenticationSuccess'):
                for element in tree[0]:
                    if element.tag.endswith('user'):
                        user = element.text
                    elif element.tag.endswith('attributes'):
                        for attribute in element:
                            attributes[attribute.tag.split("}").pop()] = \
                                attribute.text

            return user, attributes

        finally:
            page.close()


class CookieCheckHandler(BaseHandler):

    def get(self):

        self.log = logging.getLogger("h5serv")
        self.log.info('CookieCheckHandler:get() called')

        # Read the cookie, save user information
        self.get_current_user()
        self.log.info('self.username: ' + str(self.username))

        if self.username:
            # return self.write({'message': True})
            # return self.write({'message': True, 'username': self.username})
            return self.write({'message': True, 'attributes':
                              self.userattributes})
        else:
            return self.write({'message': False})


class TicketCheckHandler(BaseHandler, CasClientMixin, RequestHandler):

    def get(self):

        self.log = logging.getLogger("h5serv")
        self.log.info('TicketCheckHandler:get() called')

        # Check for a ticket in the url
        ticket = self.get_argument('ticket', None)
        self.log.info('ticket: ' + str(ticket))

        if ticket:

            # Verify the ticket with the CAS server
            username, attributes = self.verify_cas(ticket, self.service_url)

            self.log.info('username:   ' + str(username))
            self.log.info('attributes: ' + str(attributes))

            # Save the information to a cookie
            self.log.info('creating cookie')
            self.set_secure_cookie('cas_attributes', json.dumps(attributes))

            # Save to global variables
            self.username = username

        else:
            self.username = None

        # # Read the cookie, save user information
        # self.get_current_user()
        # self.log.info('self.username: ' + str(self.username))

        if self.username:
            return self.write({'message': True})
        else:
            return self.write({'message': False})


class LoginHandler(BaseHandler, CasClientMixin, RequestHandler):

    def get(self):
        self.log = logging.getLogger("h5serv")
        self.log.info('LoginHandler:get() called')

        self.get_current_user()
        self.log.info('self.username: ' + str(self.username))

        if self.username:
            return self.write({'message': 'login success'})

        ticket = self.get_argument('ticket', None)
        self.log.info('ticket: ' + str(ticket))

        if ticket:
            username, attributes = self.verify_cas(ticket, self.service_url)

            self.log.info('username:   ' + str(username))
            self.log.info('attributes: ' + str(attributes))

            self.set_secure_cookie('cas_attributes', json.dumps(attributes))

            self.log.info('yes ticket, redirecting to: /')

            return self.redirect('/')
        else:
            self.log.info('no ticket, redirecting to: ' + self.get_login_url())
            return self.redirect(self.get_login_url())


class LogoutHandler(CasClientMixin, BaseHandler):
    def get(self):
        self.log = logging.getLogger("h5serv")
        self.log.info('LogoutHandler:get() called')

        # Clear the CAS cookie
        self.clear_cookie('cas_attributes')

        # Read the cookie, hopefully no longer there
        # self.get_current_user()
        # self.log.info('self.username: ' + str(self.username))
        self.username = None
        self.userid = -1
        self.usergroupids = []
        self.log.info('self.username: ' + str(self.username))

        if self.username:
            return self.write({'message': True})
        else:
            return self.write({'message': False})


def sig_handler(sig, frame):
    log = logging.getLogger("h5serv")
    log.warning('Caught signal: %s', sig)
    IOLoop.instance().add_callback(shutdown)


def shutdown():
    log = logging.getLogger("h5serv")
    MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 2
    log.info('Stopping http server')

    log.info(
        'Will shutdown in %s seconds ...', MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
    io_loop = tornado.ioloop.IOLoop.instance()

    deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

    def stop_loop():
        now = time.time()
        if now < deadline and (io_loop._callbacks or io_loop._timeouts):
            io_loop.add_timeout(now + 1, stop_loop)
        else:
            io_loop.stop()
            log.info('Shutdown')
    stop_loop()

    log.info("closing db")


def make_app():
    static_url = config.get('static_url')
    static_path = config.get('static_path')
    settings = {}
    config_debug = config.get('debug')
    if type(config_debug) is str:
        if config_debug[0] in ('T', 't'):
            settings["debug"] = True
        else:
            settings["debug"] = False
    else:
        settings["debug"] = config_debug

    # Settings for CAS
    settings['cookie_secret'] = 'blahblah'

    favicon_path = "favicon.ico"
    print("dirname path:", os.path.dirname(__file__))
    print("favicon_path:", favicon_path)
    print('Static content in the path:' + static_path +
          " will be displayed via the url: " + static_url)
    print('isdebug:', settings['debug'])

    app = Application([
        url(r"/datasets/.*/type", DatatypeHandler),
        url(r"/datasets/.*/shape", ShapeHandler),
        url(r"/datasets/.*/attributes/.*", AttributeHandler),
        url(r"/datasets/.*/acls/.*", AclHandler),
        url(r"/datasets/.*/acls", AclHandler),
        url(r"/groups/.*/attributes/.*", AttributeHandler),
        url(r"/groups/.*/acls/.*", AclHandler),
        url(r"/groups/.*/acls", AclHandler),
        url(r"/datatypes/.*/attributes/.*", AttributeHandler),
        url(r"/datasets/.*/attributes", AttributeHandler),
        url(r"/groups/.*/attributes", AttributeHandler),
        url(r"/datatypes/.*/attributes", AttributeHandler),
        url(r"/datatypes/.*/acls/.*", AclHandler),
        url(r"/datatypes/.*/acls", AclHandler),
        url(r"/datatypes/.*", TypeHandler),
        url(r"/datatypes/", TypeHandler),
        url(r"/datatypes\?.*", TypeCollectionHandler),
        url(r"/datatypes", TypeCollectionHandler),
        url(r"/datasets/.*/value", ValueHandler),
        url(r"/datasets/.*/value\?.*", ValueHandler),
        url(r"/datasets/.*", DatasetHandler),
        url(r"/datasets/", DatasetHandler),
        url(r"/datasets\?.*", DatasetCollectionHandler),
        url(r"/datasets", DatasetCollectionHandler),
        url(r"/groups/.*/links/.*", LinkHandler),
        url(r"/groups/.*/links\?.*", LinkCollectionHandler),
        url(r"/groups/.*/links", LinkCollectionHandler),
        url(r"/groups/", GroupHandler),
        url(r"/groups/.*", GroupHandler),
        url(r"/groups\?.*", GroupCollectionHandler),
        url(r"/groups", GroupCollectionHandler),
        url(r"/info", InfoHandler),
        url(static_url, tornado.web.StaticFileHandler,
            {'path': static_path}),
        url(r"/(favicon\.ico)",
            tornado.web.StaticFileHandler, {'path': favicon_path}),
        url(r"/acls/.*", AclHandler),
        url(r"/acls", AclHandler),
        url(r'/cookiecheck', CookieCheckHandler),
        url(r'/ticketcheck/?', TicketCheckHandler),
        url(r'/login/?', LoginHandler),
        url(r'/logout', LogoutHandler),
        url(r"/", RootHandler),
        url(r".*", DefaultHandler),
    ],  **settings)
    return app


#
# update TOC when files are added via some out of process method
# (e.g. scp to the server)
#
def updateToc(filepath):
    log = logging.getLogger("h5serv")
    log.info("updateToc(%s)", filepath)
    if os.name == 'nt':
        filepath = filepath.replace('\\', '/')  # match HDF5 convention
    hdf5_ext = config.get('hdf5_ext')
    if not filepath.endswith(hdf5_ext):
        log.info("ignoring non-HDF5 file added to data directory")
        return

    if filepath.endswith(config.get('toc_name')):
        log.info("ignore toc file creation")
        return

    base_domain = fileUtil.getDomain(filepath)
    log.info("base domain: " + base_domain)

    try:
        if fileUtil.isFile(filepath):
            tocUtil.addTocEntry(base_domain, filepath)
        else:
            tocUtil.removeTocEntry(base_domain, filepath)
    # except IOError as e:
    except IOError:
        log.info("periodic callback: unable to update toc")


#
# Background processing callback
#
def periodicCallback():
    # callback for background processing
    log = logging.getLogger("h5serv")
    # log.info("periodicCallback")
    # check event queue
    while not event_queue.empty():
        item = event_queue.get()
        log.info("process_queue, got: %s", item)
        # just add file events for now
        updateToc(item)


def main():
    # os.chdir(config.get('datapath'))

    app_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    os.chdir(app_dir)

    # create logger
    log = logging.getLogger("h5serv")
    log_file = config.get("log_file")
    log_level = config.get("log_level")

    # add file handler if given in config
    if log_file:
        print("Using logfile: ", log_file)
        # set daily rotating log

        handler = logging.handlers.TimedRotatingFileHandler(
            log_file,
            when="midnight",
            interval=1,
            backupCount=0,
            utc=True)

        # add formatter to handler
        # create formatter
        formatter = logging.Formatter(
            "%(asctime)s:%(levelname)s:%(filename)s:%(lineno)d::%(message)s")
        handler.setFormatter(formatter)
        # add handler to logger
        log.addHandler(handler)
    else:
        print("No logfile")

    # add default logger (to stdout)
    handler = logging.StreamHandler(sys.stdout)
    # create formatter
    formatter = logging.Formatter(
        "%(levelname)s:%(filename)s:%(lineno)d::%(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.propagate = False  # otherwise, we'll get repeated lines

    password_uri = "none"
    x = "password_uri"
    if x.upper() in os.environ:
        password_uri = os.environ[x.upper()]
    password_uri = config.get("password_uri")
    print("password_uri config:", password_uri)

    # log levels: ERROR, WARNING, INFO, DEBUG, or NOTSET
    if not log_level or log_level == "NOTSET":
        log.setLevel(logging.NOTSET)
    if log_level == "ERROR":
        print("Setting log level to: ERROR")
        log.setLevel(logging.ERROR)
    elif log_level == "WARNING":
        print("Setting log level to: WARNING")
        log.setLevel(logging.WARNING)
    elif log_level == "INFO":
        print("Setting log level to: INFO")
        log.setLevel(logging.INFO)
    elif log_level == "DEBUG":
        print("Setting log level to: DEBUG")
        log.setLevel(logging.DEBUG)
    else:
        print("No logging!")
        log.setLevel(logging.NOTSET)

    log.info("log test")

    app = make_app()
    domain = config.get("domain")
    print("domain:", domain)

    ssl_cert = config.get('ssl_cert')
    if ssl_cert:
        print("ssl_cert:", ssl_cert)
    ssl_key = config.get('ssl_key')
    if ssl_key:
        print("ssl_key:", ssl_key)
    ssl_port = config.get('ssl_port')
    if ssl_port:
        print("ssl_port:", ssl_port)

    #
    # Setup listener for changes in the file system
    #
    data_path = config.get('datapath')
    global event_queue
    event_queue = Queue()
    # implemented in h5watchdog.py
    background_timeout = int(config.get("background_timeout"))
    if background_timeout:
        print("Setting watchdog on: ", data_path)
        h5observe(data_path, event_queue)
        tornado.ioloop.PeriodicCallback(periodicCallback, 1000).start()

    #
    # Insantiate auth class
    #
    global auth
    auth = getAuthClient()

    if ssl_cert and op.isfile(ssl_cert) and ssl_key and op.isfile(ssl_key) \
            and ssl_port:
        ssl_cert_pwd = config.get('ssl_cert_pwd')
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(ssl_cert, keyfile=ssl_key,
                                password=ssl_cert_pwd)
        ssl_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
        ssl_server.listen(ssl_port)
        msg = "Running SSL on port: " + str(ssl_port) + " (SSL)"
    else:
        server = tornado.httpserver.HTTPServer(app, xheaders=True)
        port = int(config.get('port'))
        server.listen(port)
        msg = "Starting event loop on port: " + str(port)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    log.info("INITIALIZING...")
    log.info(msg)
    print(msg)

    IOLoop.current().start()


if __name__ == "__main__":
    main()
