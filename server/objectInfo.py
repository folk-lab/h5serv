#!/usr/bin/python

'''
More potentially useless functions, but I could just not figure out how to get
the information I wanted from the existing functions in h5serv and h5df-json,
namely for a given file path plus path within a file, get the uuid of the
object.
'''

#####################
# IMPORT LIBRARIES ##
#####################

# HDF5
import h5py

# General systems
import argparse
import os.path
import sys

# Global variables
DEBUG_MODE = False
H5PATH = False
DIRPATH = False
F1 = False
LIST_OF_OBJECTS = []


###########
# HELPERS #
###########

def add_to_list_of_objects(name, obj):

    if DEBUG:
        print '  -> ' + name

    global LIST_OF_OBJECTS
    LIST_OF_OBJECTS.append(name)

    if DEBUG:
        for key, val in obj.attrs.iteritems():
            print "    -> %s: %s" % (key, val)


def list_file_contents(data_path, input_file, debug):

    global DEBUG
    DEBUG = debug
    global LIST_OF_OBJECTS
    LIST_OF_OBJECTS = []

    # Open the file, see what's there
    input_file = data_path + input_file
    if debug:
        print 'input_file: ' + input_file
    f2 = h5py.File(input_file, 'r')
    f2.visititems(add_to_list_of_objects)
    f2.close()
    for name in LIST_OF_OBJECTS:
        print name

    return LIST_OF_OBJECTS


def get_uuid(data_path, toc_name, file_path, h5_path, debug):
    '''
    Get the UUID of an object within an HDF5 file
    '''

    # The given file path is relative to the data directory
    file_path = data_path + file_path
    toc_name = data_path + toc_name
    if debug:
        print 'file_path: ' + file_path
        print 'toc_name: ' + toc_name

    uuid = False

    # Is this a file?
    if os.path.isfile(file_path):

        # Just a file
        if str(h5_path) == '' or str(h5_path) is None or \
                str(h5_path) == 'None':
            if debug:
                print 'calling get_uuid_file'
            uuid = get_uuid_file(file_path, debug)

        # An object within a file
        else:
            if debug:
                print 'calling get_uuid_h5object'
            uuid = get_uuid_h5object(file_path, h5_path, debug)

    # Is this a folder?
    if os.path.isdir(file_path):
        uuid = get_uuid_dir(toc_name, file_path, debug)

    return uuid


def get_uuid_dir(toc_name, file_path, debug):

    global DEBUG_MODE
    global DIRPATH
    DEBUG_MODE = debug
    DIRPATH = file_path.replace('../data/', '')

    # Check if the toc file exists
    if not os.path.isfile(toc_name):
        return False

    # Check if the data file's toc file exists
    if not os.path.isfile(toc_name):
        return False

    # Open the hdf5 file, make it global inorder to use it in another function
    global F1
    F1 = h5py.File(toc_name, 'r')

    if debug:
        print ''
        print '**** PRINT ATTRS ****'
        print ''
        F1.visititems(print_attrs)
        print ''
        print '**** FIND_DIR ****'
        print ''

    uuid = F1.visititems(find_dir)

    # The global file needs to be explicitly closed!
    F1.close()

    if debug:
        print 'uuid: ' + str(uuid)

    if uuid is None:
        return False

    return uuid


def get_uuid_file(file_path, debug):

    # Assemble the likely toc filename for this data file
    toc_name_full_name = os.path.dirname(file_path) + '/.' + \
        os.path.basename(file_path)
    if debug:
        print 'toc_name_full_name: ' + toc_name_full_name

    # Check if the data file's toc file exists
    if not os.path.isfile(toc_name_full_name):
        return False

    # Open the hdf5 file
    f1 = h5py.File(toc_name_full_name, 'r')

    if debug:
        print ''
        print '**** PRINT ATTRS ****'
        print ''
        f1.visititems(print_attrs)

    uuid = f1.visititems(find_file)

    if debug:
        print 'uuid: ' + str(uuid)

    if uuid is None:
        return False

    return uuid


def get_uuid_h5object(file_path, h5_path, debug):

    # Set some global variables
    global DEBUG_MODE
    global H5PATH
    DEBUG_MODE = debug
    H5PATH = '/' + h5_path

    if debug:
        print 'H5PATH: ' + H5PATH

    # Assemble the likely toc filename for this data file
    toc_name_full_name = os.path.dirname(file_path) + '/.' + \
        os.path.basename(file_path)
    if debug:
        print 'toc_name_full_name: ' + toc_name_full_name

    # Check if the data file's toc file exists
    if not os.path.isfile(toc_name_full_name):
        return False

    # Open the hdf5 file
    f1 = h5py.File(toc_name_full_name, 'r')

    if debug:
        print ''
        print '**** PRINT ATTRS ****'
        print ''
        f1.visititems(print_attrs)

    uuid = f1.visititems(find_h5_object_uuid)

    if debug:
        print 'uuid: ' + str(uuid)

    if uuid is None:
        return False

    return uuid


def print_attrs(name, obj):

    print '* name: ' + name
    for key, val in obj.attrs.iteritems():
        print "    %s: %s" % (key, val)


def find_dir(name, obj):
    '''
    '''

    # Look for a st of group == folders
    if '{groups}' in name:
        if DEBUG_MODE:
            print name

        for key, val in obj.attrs.iteritems():

            if DEBUG_MODE:
                print ""
                print "    %s: %s" % (key, val)

            # return key

            # Dereference the HDF5 object
            obj = F1[val]

            # Get the folder name
            stupid_string = str(obj)
            chopped_string = stupid_string.split('"')
            chopped_string = chopped_string[1][1:]

            if DEBUG_MODE:
                print 'object:      ' + stupid_string
                print 'parsed:      ' + chopped_string
                print 'looking for: ' + str(DIRPATH)

            # See if this is what we're after
            if str(DIRPATH) == chopped_string:
                if DEBUG_MODE:
                    print "    %s: %s" % (key, val)
                    print 'Yeah!'

                return key


def find_file(name, obj):
    '''
    '''

    # Not sure the best way to do this, but looking for mtime or ctime seems
    # give the correct uuid...
    if '{mtime}' in name:
        if DEBUG_MODE:
            print name

        for key, val in obj.attrs.iteritems():
            if DEBUG_MODE:
                print "    %s: %s" % (key, val)
                print 'Yeah!'

            return key


def find_h5_object_reference(name, obj):
    '''
    '''

    # We're only really interested in the groups (folders) and datasets
    # (images, text, etc.) that are in this file
    if '{groups}' in name or '{datasets}' in name:
        if DEBUG_MODE:
            print name

        for key, val in obj.attrs.iteritems():
            if DEBUG_MODE:
                print "    %s: %s" % (key, val)

            if str(H5PATH) == str(val):

                if DEBUG_MODE:
                    print 'Yeah!'

                return key


def find_h5_object_uuid(name, obj):
    '''
    '''

    # We're only really interested in the groups (folders) and datasets
    # (images, text, etc.) that are in this file
    if '{groups}' in name or '{datasets}' in name:
        if DEBUG_MODE:
            print name

        for key, val in obj.attrs.iteritems():
            if DEBUG_MODE:
                print "    %s: %s" % (key, val)

            if str(H5PATH) == str(val):

                if DEBUG_MODE:
                    print 'Yeah!'

                return key


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
    parser.add_argument("-dp", '--data_path', required=False,
                        default='../data/',
                        help='the uuid of the object to find')
    parser.add_argument("-t", '--toc_name', required=False,
                        default='.toc.h5',
                        help='the uuid of the object to find')
    parser.add_argument("-f", '--file_path', required=False,
                        default='example-subfolder/new-file.h5',
                        help='the hdf5 file path, relative to data directory')
    parser.add_argument("-h5", '--h5_path', required=False,
                        default='',
                        help='the path within the hdf5 file')
    parser.add_argument('-l', '--list_contents', action='store_true',
                        help='List the contents of the input HDF5 file')
    parser.add_argument('-u', '--get_uuid', action='store_true',
                        help='Get the UUID of the object')

    # Print a little extra in addition to the standard help message
    if len(argv) == 0 or '-h' in argv or '--help' in argv:
        try:
            args = parser.parse_args(['-h'])
        except SystemExit:
            print ''
            print 'Examples of usage:'
            print ''
            print('python ../server/objectInfo.py -f example-subfolder/'
                  'new-file.h5 -h5 scan_1/data_1/image_0000 -u')
            print 'python ../../server/objectInfo.py -f new-file.h5 -l'
            sys.exit()
    else:
        args = parser.parse_args(argv)

    if args.debug:
        print args

    if args.get_uuid:
        uuid = get_uuid(args.data_path, args.toc_name, args.file_path,
                        args.h5_path, args.debug)

        print 'uuid: ' + str(uuid)

    if args.list_contents:
        my_list = list_file_contents(args.data_path, args.file_path,
                                     args.debug)
        if args.debug:
            print my_list


#######################
# RUN THE APPLICATION #
#######################

if __name__ == '__main__':
    main(sys.argv[1:])
