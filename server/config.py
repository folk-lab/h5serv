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
import os
import sys

cfg = {
    'port':   5000,
    'debug':  True,
    'datapath': '../data/',
    'public_dir': ['example-subfolder'],
    'domain':  'maxiv.lu.se',
    'hdf5_ext': '.h5',
    'toc_name': '.toc.h5',
    'home_dir': 'home',
    'ssl_port': 6050,
    'ssl_cert': 'cert.pem',  # add relative path to cert for SSL
    'ssl_key':  'key.pem',  # add relative path to cert key for SSL
    'ssl_cert_pwd': 'maxiv',
    'password_uri': '../util/admin/passwd.h5',
    # 'password_uri': 'mongodb://mongo:27017',
    'mongo_dbname': 'hdfdevtest',
    'static_url': r'/views/(.*)',
    'static_path': r'../static',

    # set to None to disallow CORS (cross-origin resource sharing)
    # 'cors_domain': '*',
    'cors_domain': 'https://w-jasbru-pc-0.maxiv.lu.se',
    'log_file': r'../log/h5serv.log',
    'log_level': 'DEBUG',  # ERROR, WARNING, INFO, DEBUG, or NOTSET,

    # (ms) set to 0 to disable background processing
    'background_timeout': 1000,
}


def get(x):

    # see if there is a command-line override
    option = '--'+x+'='

    for i in range(1, len(sys.argv)):

        # print i, sys.argv[i]
        if sys.argv[i].startswith(option):

            # found an override
            arg = sys.argv[i]
            return arg[len(option):]  # return text after option string

    # see if there are an environment variable override
    if x.upper() in os.environ:
        return os.environ[x.upper()]

    # no command line override, just return the cfg value
    if x in cfg:
        return cfg[x]
    else:
        return None
