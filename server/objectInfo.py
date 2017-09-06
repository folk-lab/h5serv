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


###########
# HELPERS #
###########

# Global variables
DEBUG_MODE = False
H5PATH = False


def get_uuid(toc_file, file_path, h5_path, debug):
    '''
    Get the UUID of an object within an HDF5 file
    '''

    # Set some global variables
    global H5PATH
    global DEBUG_MODE
    DEBUG_MODE = debug
    H5PATH = '/' + h5_path

    if debug:
        print 'H5PATH: ' + H5PATH

    # Check if the toc file exists
    if not os.path.isfile(toc_file):
        return False

    # Check if the data file exists
    file_path = '../data/' + file_path + '.h5'
    if debug:
        print 'file_path: ' + file_path

    if not os.path.isfile(file_path):
        return False

    # Assemble the likely toc filename for this data file
    toc_file_full_name = os.path.dirname(file_path) + '/.' + \
        os.path.basename(file_path)
    if debug:
        print 'toc_file_full_name: ' + toc_file_full_name

    # Check if the data file's toc file exists
    if not os.path.isfile(toc_file_full_name):
        return False

    # Open the hdf5 file
    f1 = h5py.File(toc_file_full_name, 'r')

    if debug:
        print ''
        print '**** PRINT ATTRS ****'
        print ''
        f1.visititems(print_attrs)

    uuid = f1.visititems(get_object_reference)

    if debug:
        print 'uuid: ' + str(uuid)

    if uuid is None:
        return False

    return uuid


def print_attrs(name, obj):

    # We're only really interested in the groups (folders) and datasets
    # (images, text, etc.)
    if '{groups}' in name or '{datasets}' in name:
        print name
        for key, val in obj.attrs.iteritems():
            print "    %s: %s" % (key, val)


def get_object_reference(name, obj):
    '''
    '''

    # We're only really interested in the groups (folders) and datasets
    # (images, text, etc.)
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
    parser.add_argument("-t", '--toc_file', required=False,
                        default='../data/.toc.h5',
                        help='the uuid of the object to find')
    parser.add_argument("-f", '--file_path', required=False,
                        default='example-subfolder/new-file',
                        help='the hdf5 file path, relative to data directory')
    parser.add_argument("-h5", '--h5_path', required=False,
                        default='scan_1/data_1/image',
                        help='the path within the hdf5 file')

    # Print a little extra in addition to the standard help message
    if '-h' in argv or '--help' in argv:
        try:
            args = parser.parse_args(['-h'])
        except SystemExit:
            print ''
            print 'Examples of usage:'
            print ''
            print '  python largeImages.py tau1-tau_2_data_000001.h5'
            sys.exit()
    else:
        args = parser.parse_args(argv)

    if args.debug:
        print args

    uuid = get_uuid(args.toc_file, args.file_path, args.h5_path,
                    args.debug)

    print 'uuid: ' + str(uuid)


#######################
# RUN THE APPLICATION #
#######################

if __name__ == '__main__':
    main(sys.argv[1:])
