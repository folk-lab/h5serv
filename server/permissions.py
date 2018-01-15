#!/usr/bin/python

'''
This is probably a useless set of functions, but I could just not figure out
how to get the information I wanted from the existing functions in h5serv
and h5df-json, namely for a given uuid referring to a folder, get the full
path name of that folder. Once the folder path is in hand, determine its
permissions and if the logged in user ought to be able to read its contents.
'''

#####################
# IMPORT LIBRARIES ##
#####################

# HDF5
import h5py

# User information
from pwd import getpwnam
from grp import getgrall, getgrgid
import stat

# General systems
import argparse
import os.path
import sys


###########
# HELPERS #
###########

# Global variables
DEBUG_MODE = False
OBJECT_UUID = False


def get_info_from_uuid(toc_file, uuid, username, debug):
    '''
    Given an object uuid and username, determine if the user has sufficient
    privelages to read the object
    '''

    if os.path.isfile(toc_file):
        folder_name = get_folder_name_from_uuid(toc_file, uuid, debug)
    else:
        if debug:
            print('the toc file ' + toc_file + ' does not exist')
        return False

    if not folder_name:
        # If no folder is found, assume that we're dealing with a folder within
        # a file, and therefore it's readable
        return True
    else:
        userid, usergroupids = get_user_info(username, debug)

        readable = can_user_read_file(folder_name, userid, usergroupids, debug)

        return readable


def find_group(name):
    """ Find first object with 'foo' anywhere in the name """
    if '{groups}' in name:
        return name


def print_attrs(name, obj):
    print(name)
    for key, val in obj.attrs.iteritems():
        print("    %s: %s" % (key, val))


def get_folder_name_from_uuid(toc_file, uuid, debug):

    if debug:
        print('**** FIND ITEM ****')
        print('')

    # Set some global variables
    global DEBUG_MODE
    global OBJECT_UUID
    DEBUG_MODE = debug
    OBJECT_UUID = uuid

    if os.path.isfile(toc_file):
        f1 = h5py.File(toc_file, 'r')
    else:
        if debug:
            print('the toc file ' + toc_file + ' does not exist')
        return False

    if debug:
        print('')
        print('**** PRINT ATTRS ****')
        print('')
        f1.visititems(print_attrs)

    my_item = f1.visititems(get_folder_reference)

    if debug:
        print('my_item: ' + str(my_item))

    if my_item is None:
        return False

    mygroup2 = f1[my_item]

    folder_name = '../data' + mygroup2.name

    if debug:
        print('folder_name: ' + str(folder_name))

    return folder_name


def get_folder_reference(name, obj):
    '''
    Return a reference to an hdf5 object, in this case it is (hopeully) a
    folder.
    As the uuid is being used, there should be a single unique match, therefore
    returning once it is found should be ok...
    '''

    for key, val in obj.attrs.items():
        if OBJECT_UUID in str(key) and '{groups}' in name:

            if DEBUG_MODE:
                print(name)
                print("    %s: %s" % (key, val))

            return val


def get_user_info(username, debug):
    '''
    Given a user name, get the user id number, group id numbers
    '''

    if debug:
        print('**** FIND USER INFO ****')
        print('')
        print('username: ' + str(username))

    # Get user id number - quick fix, Should really get this from CAS,
    # but that item is not available at this time...
    userid = getpwnam(username).pw_uid
    if debug:
        print('userid: ' + str(userid))

    # Get the groups - also a quick fix
    # The group id numbers for all groups for this user
    usergroupids = [g.gr_gid for g in getgrall() if username in g.gr_mem]

    # Get the group id number for the user name
    gid = getpwnam(username).pw_gid
    usergroupids.append(getgrgid(gid).gr_gid)

    if debug:
        print('gid: ' + str(gid))
        print('usergroupids: ' + str(usergroupids))

    return userid, usergroupids


def can_user_read_file(filepath, userid, usergroupids, debug):
    '''
    Look at the ownership and permissions of a file and determine if the logged
    in user has read access or not - ignore write access for now.
    '''

    if debug:
        print('**** FIND ITEM ****')
        print('')
        print("actual file or folder?: " + str(filepath))

    readable = False
    readable_as_owner = False
    readable_by_group = False
    readable_by_other = False

    # Get the owner and group ids, mode, and a bunch of other information
    # about the file
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = \
        os.stat(filepath)

    # Check if this is a file or directory
    if debug:
        print('stat.S_ISDIR(mode): ' + str(stat.S_ISDIR(mode)))
        print('stat.S_ISREG(mode): ' + str(stat.S_ISREG(mode)))
        print('stat.S_ISLNK(mode): ' + str(stat.S_ISLNK(mode)))

    # Check if the user is the owner and has read permissions
    if debug:
        print('uid:          ' + str(uid))
        print('userid:       ' + str(userid))

    if uid == userid:
        user_readable = bool(mode & stat.S_IRUSR)
        if user_readable:
            readable_as_owner = True

    # Check if the user is in the right group and has read permissions
    if debug:
        print('gid:          ' + str(gid))
        print('usergroupids: ' + str(usergroupids))

    if gid in usergroupids:
        group_readable = bool(mode & stat.S_IRGRP)
        if group_readable:
            readable_by_group = True

    # Check if this file is readable by others
    readable_by_other = bool(mode & stat.S_IROTH)

    if debug:
        print('readable_as_owner: ' + str(readable_as_owner))
        print('readable_by_group: ' + str(readable_by_group))
        print('readable_by_other: ' + str(readable_by_other))

    if readable_as_owner or readable_by_group or readable_by_other:
        readable = True
    else:
        readable = False

    if debug:
        print('readable: ' + str(readable))

    return readable


########
# MAIN #
########

def main(argv):
    '''
    The main function - usage and help, argument parsing
    '''

    # Setup options
    parser = argparse.ArgumentParser(
        description='Look at stuff in the h5serv toc file')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Debug output')
    parser.add_argument("-t", '--toc_file', required=False,
                        default='../data/.toc.h5',
                        help='the uuid of the object to find')
    parser.add_argument("-i", '--uuid', required=False,
                        default='55263383-19fb-11e7-b06d-080027343bb1',
                        help='the uuid of the object to find')
    parser.add_argument("-u", '--username', required=False,
                        default='jasbru',
                        help='the uuid of the object to find')

    # Print a little extra in addition to the standard help message
    if len(argv) == 0 or '-h' in argv or '--help' in argv:
        try:
            args = parser.parse_args(['-h'])
        except SystemExit:
            print('')
            print('Examples of usage:')
            print('')
            print('  python largeImages.py tau1-tau_2_data_000001.h5')
            sys.exit()
    else:
        args = parser.parse_args(argv)

    if args.debug:
        print(args)

    readable = get_info_from_uuid(args.toc_file, args.uuid, args.username,
                                  args.debug)

    print('readable: ' + str(readable))


#######################
# RUN THE APPLICATION #
#######################

if __name__ == '__main__':
    main(sys.argv[1:])
