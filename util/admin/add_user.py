import h5py
import numpy as np
import sys
import argparse
import os.path as op
import os
import time
import datetime
import hashlib
import config
 

def encrypt_pwd(passwd):
    encrypted = hashlib.sha224(passwd).hexdigest()
    return encrypted
    
def print_time(timestamp):
    str_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return str_time
    
def generate_temp_password(length=6):
    if not isinstance(length, int) or length < 4:
        raise ValueError("temp password must have positive length")

    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join([chars[ord(c) % len(chars)] for c in os.urandom(length)])
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--user", help='user id')
      
    args = parser.parse_args()
       
    filename = None
    passwd = None
    username = None
    
    filename = config.get('password_file')
    if not filename:
        print("no password file in config")
        return -1
     
    if not args.user:
        print("no userid supplied")
        return -1
         
    username = args.user
    if username.find(':') != -1:
        print "invalid username (':' is not allowed)"
        return -1
    if username.find('/') != -1:
        print "invalid username ('/' is not allowed)"
        return -1
    if username.find('@') == -1:
        print "invalid username (should be email address)"
        return -1
     
      
    passwd = generate_temp_password()
            
    print ">filename:", filename
    print ">username:", username
    print ">password:", passwd
    
        
    # verify file exists and is writable
    if not op.isfile(filename):
        print "password file:", filename, " does not exist"
        return -1
        
    if not h5py.is_hdf5(filename):
        print "invalid password file"
        return -1
        
    if not os.access(filename, os.W_OK):
        print "password file is not writable"
        return -1
    
    f = h5py.File(filename, 'r+')
    if 'user_type' not in f:
        print "invalid password file"
        return -1
        
    user_type = f['user_type']
       
    
    now = int(time.time())
    
    # add a new user
    if username in f.attrs:
        print "user already exists"
        return -1
        
    # create userid 1 greater than previous used
    userid = len(f.attrs) + 1
    data = np.empty((), dtype=user_type)
    data['pwd'] = encrypt_pwd(passwd)
    data['state'] = 'A'
    data['userid'] = userid
    data['ctime'] = now
    data['mtime'] = now
    f.attrs.create(username, data, dtype=user_type)   
    f.close()
    
    datapath = config.get('datapath')
    if not op.isdir(datapath):
        print("data directory not found")
        return -1
    
    userpath = op.join(datapath, 'users')
    if not op.isdir(userpath):
        os.mkdir(userpath)
    userdir = op.join(userpath, userid)
    if opisdir(userdir):
        print("user directory already exists")
        return -1
        
    os.mkdir(userdir)
    
    toc_name = ".toc.h5"
    f = h5py.File(toc_name, 'w')
    
    public_dir = op.join(datapath, "public")
    public_didr = 
    f['public'] = h5py.ExternalLink(filedomain, "/")
    
    
    
    
    
    return 0
     
    

main()