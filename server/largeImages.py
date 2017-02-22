#!/usr/bin/python

'''
Decimate large images so that they can be sent
'''

#####################
# IMPORT LIBRARIES ##
#####################

import hdf5plugin
import h5py
from skimage.measure import block_reduce

import argparse
import sys
import numpy

import os.path

import cProfile

import matplotlib.pyplot as pyplot

assert hdf5plugin  # silence pyflakes


###########
# HELPERS #
###########

def get_image(fileName, dataset_name, debug):
    '''
    Send the data off to the data server, which will then make it available

    '''

    # Get a nice single image from an existing file
    f1 = h5py.File(fileName, 'r')
    image = f1[dataset_name][:, :]
    f1.close()

    if debug:
        print 'image size: ', image.shape

    return image


def get_series_image(fileName, dataset_name, image_index, debug):
    '''
    Send the data off to the data server, which will then make it available

    '''

    # Get a nice single image from an existing file
    f1 = h5py.File(fileName, 'r')
    image = f1[dataset_name][image_index, :, :]
    f1.close()

    if debug:
        print 'image size: ', image.shape

    return image


def decimate_image(originalImage, image_size_limit, data_type,
                   value_dimensions, debug):
    '''
    Not sure how best to do this - max? min? sum?
    Some useful things here perhaps:
        http://scikit-image.org/docs/dev/api/skimage.measure.html
            #skimage.measure.block_reduce
    '''

    # If this is a list, convert to a numpy array - very costly for large
    # images!
    if isinstance(originalImage, list):
        if debug:
            pr = cProfile.Profile()
            pr.enable()

        originalImage = numpy.array(originalImage)

        if debug:
            pr.disable()
            pr.print_stats(sort='time')

    # The image_size_limit is assumed to be for a roughly square image
    if data_type == 2:
        downsampleX = value_dimensions[0]
    if data_type == 3:
        downsampleX = value_dimensions[1]

    downsampleX = int(numpy.ceil(downsampleX/numpy.sqrt(image_size_limit)))
    downsampleY = downsampleX

    if data_type == 2:
        block_size = (downsampleX, downsampleY)
    if data_type == 3:
        block_size = (1, downsampleX, downsampleY)

    # Perform a function on a block of pixels. Some possible functions to
    # try:
    #   numpy.sum, np.max, np.mean, numpy.min
    # Perhaps numpy.sum is the best thing to do?
    if debug:
        pr = cProfile.Profile()
        pr.enable()

    image_sum = block_reduce(
        originalImage,
        block_size=block_size,
        func=numpy.sum
        # func=numpy.max
        )

    if debug:
        pr.disable()
        pr.print_stats(sort='time')

        print 'image size: ', image_sum.shape
        print image_sum

    return image_sum


def get_data_type(values, debug):
    '''
    It's best to send numpy.ndarray object to this function instead of lists,
    otherwise the list will ned to be converted to a numpy.ndarray object,
    which can be slow, on the order of 1.5 seconds for a 16 MB image on my
    laptop
    '''

    data_type = 0  # 0 == whatever, 1 == array, 2 == image, 3 == image stack
    value_dimensions = []

    if isinstance(values, list):
        value_dimensions.append(len(values))
        data_type = 1
        if isinstance(values[0], list):
            value_dimensions.append(len(values[0]))
            data_type = 2
            if isinstance(values[0][0], list):
                value_dimensions.append(len(values[0][0]))
                data_type = 3

    if isinstance(values, numpy.ndarray):
        value_dimensions = values.shape
        data_type = len(value_dimensions)

        if debug:
            print '  shape: ', values.shape

    if debug:
        print '  data_type: ', data_type
        print '  value_dimensions: ', value_dimensions

    return data_type, value_dimensions


def check_image_size(data_type, value_dimensions, size_limit, debug):

    is_big_image = False

    if data_type == 2:
        if value_dimensions[0]*value_dimensions[1] > size_limit:
            is_big_image = True

    if data_type == 3:
        if value_dimensions[1]*value_dimensions[2] > size_limit:
            is_big_image = True

    if debug:
        print '  is_big_image: ', is_big_image

    return is_big_image


def check_if_mx_file(file_path, debug):

    if debug:
        print 'check_if_mx_file.file_path:' + file_path

    is_mx_file = False
    master_file_path = False

    if '_data_' in file_path:
        file_pieces = file_path.split('/')
        data_file_name = file_pieces[-1]

        if debug:
            print 'data_file_name: ' + data_file_name

        is_mx_file = True

        # The master file name should follow a certain pattern
        file_extension = data_file_name.split('.')[-1]
        master_file_name = data_file_name.split('_data_')[0] + \
            '_master.' + file_extension
        master_file_path = ''
        for piece in file_pieces[:-1]:
            master_file_path += piece + '/'
        master_file_path += master_file_name
        does_master_file_exist = os.path.isfile(master_file_path)

        if debug:
            print 'master_file_name: ' + master_file_name
            print 'master_file_path: ' + master_file_path
            print 'does_master_file_exist: ' + str(does_master_file_exist)

    return is_mx_file, master_file_path


def get_image_mask(master_file_path, debug):

    if debug:
        print 'get_image_mask.master_file_path:' + master_file_path

    mask_image = 'entry/instrument/detector/detectorSpecific/pixel_mask'

    image_mask = get_image(master_file_path, mask_image, debug)

    return image_mask


def decimate_if_necessary(values, file_path, output_list, debug):

    if debug:
        print '  type: ' + str(type(values))

    # The input type is assumed to be numpy.ndarray, could also be a list, but
    # if it's neither of these, just return the input
    if not isinstance(values, numpy.ndarray) and \
            not isinstance(values, list):
        return values

    # Check the dataset dimensions and if it falls under my definition of a
    # 'big image'
    data_type, value_dimensions = get_data_type(values, debug)
    is_big_image = check_image_size(data_type, value_dimensions, 5e5, debug)

    # Check (in a dumb way) if this is an MX-Cube file
    is_mx_file, master_file_path = check_if_mx_file(file_path, debug)

    # If it is an MX file, get the image mask and apply it
    if is_mx_file and master_file_path:
        image_mask = get_image_mask(master_file_path, debug)
        image_out = apply_image_mask(values, data_type, image_mask, 1, 0,
                                     debug)
    else:
        image_out = values

    # Decimate if needed, up to the given maximum image size - less than 1e6
    # pixels seems good, closer to 1e5 seems to result in best results in the
    # web browser
    if is_big_image:
        image_out = decimate_image(image_out, 2e5, data_type, value_dimensions,
                                   debug)

    # Convert a numpy.ndarray to a list, which is what h5serv expects
    if output_list and isinstance(image_out, numpy.ndarray):
        image_out = image_out.tolist()

    return image_out


def apply_image_mask(image, data_type, image_mask, mask_value, new_value,
                     debug):

    # Apply the mask using the given mask value (probably 1 or greater?) then
    # replace masked pixels with the new_value (0 seems to be a good choice)
    indicies = (image_mask >= mask_value)
    image_new = numpy.copy(image)

    if data_type == 2:
        image_new[indicies] = new_value
    if data_type == 3:
        image_new[:, indicies] = new_value

    return image_new


########
# MAIN #
########

def main(argv):
    '''
    The main function - usage and help, argument parsing
    '''

    # Setup options
    parser = argparse.ArgumentParser(
        description='Reduce (downsample) an image contained in an hdf5 file')
    parser.add_argument("input_file", nargs=1,
                        help='The input hdf5 file name')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Debug output')
    parser.add_argument("-i", '--image_index', required=False, default=0,
                        help='series index for the desired image')
    parser.add_argument("-m", '--mask_file', required=False,
                        default='tau1-tau_2_master.h5',
                        help='series index for the desired image')
    parser.add_argument('-g', '--graphical_display', action='store_true',
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

    image_org = get_series_image(args.input_file[0], 'entry/data/data', 0,
                                 args.debug)

    # Check the dataset dimensions and if it falls under my definition of a
    # 'big image'
    data_type, value_dimensions = get_data_type(image_org, args.debug)

    # Check (in a dumb way) if this is an MX-Cube file
    is_mx_file, master_file_path = check_if_mx_file(args.input_file[0],
                                                    args.debug)

    # If it is an MX file, get the image mask and apply it
    if is_mx_file and master_file_path:
        image_mask = get_image_mask(master_file_path, args.debug)
        image_out = apply_image_mask(image_org, data_type, image_mask, 1, 0,
                                     args.debug)
    else:
        image_out = image_org

    image_final = decimate_if_necessary(image_org, args.input_file[0],
                                        False, args.debug)

    if args.debug:
        print ' image_org size: ', image_org.shape
        print ' image_mask size: ', image_mask.shape
        print ' image_masked size: ', image_out.shape
        print ' image_final size: ', image_final.shape

    if args.graphical_display:
        fig, axes = pyplot.subplots(2, 3)
        axes[0][0].imshow(image_org)
        axes[1][0].imshow(image_mask)
        axes[0][1].imshow(image_out)
        axes[1][1].imshow(numpy.log(image_out))
        axes[0][2].imshow(image_final)
        axes[1][2].imshow(numpy.log(image_final))
        pyplot.show()


#######################
# RUN THE APPLICATION #
#######################

if __name__ == '__main__':
    main(sys.argv[1:])
