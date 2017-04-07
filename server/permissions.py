#!/usr/bin/python

'''
Decimate large images so that they can be sent
'''

#####################
# IMPORT LIBRARIES ##
#####################

import hdf5plugin
import h5py

import argparse
import sys
import numpy

import os.path

assert hdf5plugin  # silence pyflakes


###########
# HELPERS #
###########

def get_info_from_uuid(fileName, uuid, debug):
    '''
    Given a uuid, get information about the object if it exists
    '''

    # Get a nice single image from an existing file
    f1 = h5py.File(fileName, 'r')

    for group in f1:
        print group

    return True


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

    # Print a little extra in addition to the standard help message
    if len(argv) == 0 or '-h' in argv or '--help' in argv:
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

    toc_file = '../data/.toc.h5'

    get_info_from_uuid(toc_file,
                       '55263383-19fb-11e7-b06d-080027343bb1', args.debug)


#######################
# RUN THE APPLICATION #
#######################

if __name__ == '__main__':
    main(sys.argv[1:])
