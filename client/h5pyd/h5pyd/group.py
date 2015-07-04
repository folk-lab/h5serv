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

from __future__ import absolute_import

import posixpath as pp

import six
import sys
import numpy
import collections
import json

from . import base
from .base import HLObject, MutableMappingHDF5, phil, with_phil
from . import objectid
from .objectid import ObjectID, TypeID, GroupID, DatasetID
from .dataset import Dataset
from .datatype import Datatype


class Group(HLObject, MutableMappingHDF5):

    """ Represents an HDF5 group.
    """

    def __init__(self, bind):
        #print "group init, bind:", bind
             
        
        """ Create a new Group object by binding to a low-level GroupID.
        """
        
        with phil:
            if not isinstance(bind, GroupID):
                raise ValueError("%s is not a GroupID" % bind)
            HLObject.__init__(self, bind)
            
         

    def create_group(self, name):
        """ Create and return a new subgroup.

        Name may be absolute or relative.  Fails if the target name already
        exists.
        """
        body = {'link': { 'id': self.id.uuid, 
                          'name': name 
               } }
        rsp = self.POST('/groups', body=body)
      
        group_json = json.loads(rsp.text)
        groupId = GroupID(self, group_json)
        
        subGroup = Group(groupId)
        if self._name:
            if self._name[-1] == '/':
                subGroup._name = self._name + name
            else:
                subGroup._name = self._name + '/' + name
        return subGroup
        
    def create_dataset(self, name, shape=None, dtype=None, data=None, **kwds):
        """ Create a new HDF5 dataset

        name
            Name of the dataset (absolute or relative).  Provide None to make
            an anonymous dataset.
        shape
            Dataset shape.  Use "()" for scalar datasets.  Required if "data"
            isn't provided.
        dtype
            Numpy dtype or string.  If omitted, dtype('f') will be used.
            Required if "data" isn't provided; otherwise, overrides data
            array's dtype.
        data
            Provide data to initialize the dataset.  If used, you can omit
            shape and dtype arguments.

        Keyword-only arguments:

        chunks
            (Tuple) Chunk shape, or True to enable auto-chunking.
        maxshape
            (Tuple) Make the dataset resizable up to this shape.  Use None for
            axes you want to be unlimited.
        compression
            (String or int) Compression strategy.  Legal values are 'gzip',
            'szip', 'lzf'.  If an integer in range(10), this indicates gzip
            compression level. Otherwise, an integer indicates the number of a
            dynamically loaded compression filter.
        compression_opts
            Compression settings.  This is an integer for gzip, 2-tuple for
            szip, etc. If specifying a dynamically loaded compression filter
            number, this must be a tuple of values.
        scaleoffset
            (Integer) Enable scale/offset filter for (usually) lossy
            compression of integer or floating-point data. For integer
            data, the value of scaleoffset is the number of bits to
            retain (pass 0 to let HDF5 determine the minimum number of
            bits necessary for lossless compression). For floating point
            data, scaleoffset is the number of digits after the decimal
            place to retain; stored values thus have absolute error
            less than 0.5*10**(-scaleoffset).
        shuffle
            (T/F) Enable shuffle filter.
        fletcher32
            (T/F) Enable fletcher32 error detection. Not permitted in
            conjunction with the scale/offset filter.
        fillvalue
            (Scalar) Use this value for uninitialized parts of the dataset.
        track_times
            (T/F) Enable dataset creation timestamps.
        """
        pass
        """
        with phil:
            dsid = dataset.make_new_dset(self, shape, dtype, data, **kwds)
            dset = dataset.Dataset(dsid)
            if name is not None:
                self[name] = dset
            return dset
        """
        return "todo"

    def require_dataset(self, name, shape, dtype, exact=False, **kwds):
        """ Open a dataset, creating it if it doesn't exist.

        If keyword "exact" is False (default), an existing dataset must have
        the same shape and a conversion-compatible dtype to be returned.  If
        True, the shape and dtype must match exactly.

        Other dataset keywords (see create_dataset) may be provided, but are
        only used if a new dataset is to be created.

        Raises TypeError if an incompatible object already exists, or if the
        shape or dtype don't match according to the above rules.
        """
        pass
        """
        with phil:
            if not name in self:
                return self.create_dataset(name, *(shape, dtype), **kwds)

            dset = self[name]
            if not isinstance(dset, dataset.Dataset):
                raise TypeError("Incompatible object (%s) already exists" % dset.__class__.__name__)

            if not shape == dset.shape:
                raise TypeError("Shapes do not match (existing %s vs new %s)" % (dset.shape, shape))

            if exact:
                if not dtype == dset.dtype:
                    raise TypeError("Datatypes do not exactly match (existing %s vs new %s)" % (dset.dtype, dtype))
            elif not numpy.can_cast(dtype, dset.dtype):
                raise TypeError("Datatypes cannot be safely cast (existing %s vs new %s)" % (dset.dtype, dtype))

            return dset
        """
        return "todo"
        
    def require_group(self, name):
        """ Return a group, creating it if it doesn't exist.

        TypeError is raised if something with that name already exists that
        isn't a group.
        """
         
        with phil:
            if not name in self:
                return self.create_group(name)
            grp = self[name]
            if not isinstance(grp, Group):
                raise TypeError("Incompatible object (%s) already exists" % grp.__class__.__name__)
            return grp
            
   
        

    def __getitem__(self, name):
        """ Open an object in the file """
        
        """
        #todo - get reference
        if isinstance(name, h5r.Reference):
            oid = h5r.dereference(name, self.id)
            if oid is None:
                raise ValueError("Invalid HDF5 object reference")
        else:
            oid = h5o.open(self.id, self._e(name), lapl=self._lapl)
        """
        
         
        parent = self
        tgt = None
        
        tgt_name = None
        
        if name[0] == '/':
            tgt_name = name # assign as name of returned obj
            #abs path, start with root
            if self.name != '/':
                # get root_uuid
                rsp = self.GET('/')
                root_uuid = rsp['root']
                req = "/groups/" + root_uuid
                root_json = self.GET(req)
                parent = Group(GroupID(self, root_json))
        else:
            if self.name:
                if self.name[-1] == '/':
                    tgt_name = self.name + name
                else:
                    tgt_name = self.name + '/' + name
            else:
                tgt_name = name
            
        path = name.split('/')         
                
                      
        
        for name in path:
            if not name: 
                continue
            
            if not isinstance(parent, Group):
                raise IOError("Invalid path")    
                 
            req = "/groups/" + parent.id.uuid + "/links/" + name
            rsp_json = self.GET(req)
            if "link" not in rsp_json:
                raise IOError("Unexpected Error")
            link_json = rsp_json['link']
            #print "link_json", link_json
            if link_json['class'] == 'H5L_TYPE_HARD':
                #print "hard link, collection:", link_json['collection']
                link_obj = None
                if link_json['collection'] == 'groups':
                    group_uuid = link_json['id']
                    req = "/groups/" + group_uuid
                    # do a GET to validate the object is still there
                    group_json = self.GET(req)
                    parent = Group(GroupID(self, group_json))
                    tgt = parent
                elif link_json['collection'] == 'datatypes':
                    datatype_uuid = link_json['id']
                    req = "/datatypes/" + datatype_uuid
                    datatype_json = self.GET(req)
                
                    parent = Datatype(TypeID(self, datatype_json))
                    tgt = parent
                elif link_json['collection'] == 'datasets':
                    dataset_uuid = link_json['id']
                    req = "/datasets/" + dataset_uuid
                    dataset_json = self.GET(req)
                    parent = Dataset(DatasetID(self, dataset_json)) 
                    tgt = parent        
                else:
                    raise IOError("Unexpected Error - collection type: " + link_json['collection'])
                 
        
        if tgt:
            tgt._name = tgt_name
        return tgt     
                
        """
        otype = h5i.get_type(oid)
        if otype == h5i.GROUP:
            return Group(oid)
        elif otype == h5i.DATASET:
            return dataset.Dataset(oid)
        elif otype == h5i.DATATYPE:
            return datatype.Datatype(oid)
        else:
            raise TypeError("Unknown object type")
        """

    def get(self, name, default=None, getclass=False, getlink=False):
        """ Retrieve an item or other information.

        "name" given only:
            Return the item, or "default" if it doesn't exist

        "getclass" is True:
            Return the class of object (Group, Dataset, etc.), or "default"
            if nothing with that name exists

        "getlink" is True:
            Return HardLink, SoftLink or ExternalLink instances.  Return
            "default" if nothing with that name exists.

        "getlink" and "getclass" are True:
            Return HardLink, SoftLink and ExternalLink classes.  Return
            "default" if nothing with that name exists.

        Example:

        >>> cls = group.get('foo', getclass=True)
        >>> if cls == SoftLink:
        ...     print '"foo" is a soft link!'
        """
        
        with phil:
            if not (getclass or getlink):
                try:
                    return self[name]
                except KeyError:
                    return default

            if not name in self:
                return default

            elif getclass and not getlink:
                obj = self.__getitem__[name]
                if obj is None:
                    return None
                if obj.id.__class__ is GroupID:
                    return Group
                elif obj.id.__class__ is DatasetID:
                    return Dataset
                elif obj.id.__class__ is DatatypeID:
                    return Datatype
                else:
                    raise TypeError("Unknown object type")
                 

            elif getlink:
                typecode = self.id.links.get_info(self._e(name)).type

                if typecode == h5l.TYPE_SOFT:
                    if getclass:
                        return SoftLink
                    linkbytes = self.id.links.get_val(self._e(name))
                    return SoftLink(self._d(linkbytes))
                elif typecode == h5l.TYPE_EXTERNAL:
                    if getclass:
                        return ExternalLink
                    filebytes, linkbytes = self.id.links.get_val(self._e(name))
                    # TODO: I think this is wrong,
                    # we should use filesystem decoding on the filename
                    return ExternalLink(self._d(filebytes), self._d(linkbytes))
                elif typecode == h5l.TYPE_HARD:
                    return HardLink if getclass else HardLink()
                else:
                    raise TypeError("Unknown link type")
        

    def __setitem__(self, name, obj):
        """ Add an object to the group.  The name must not already be in use.

        The action taken depends on the type of object assigned:

        Named HDF5 object (Dataset, Group, Datatype)
            A hard link is created at "name" which points to the
            given object.

        SoftLink or ExternalLink
            Create the corresponding link.

        Numpy ndarray
            The array is converted to a dataset object, with default
            settings (contiguous storage, etc.).

        Numpy dtype
            Commit a copy of the datatype as a named datatype in the file.

        Anything else
            Attempt to convert it to an ndarray and store it.  Scalar
            values are stored as scalar datasets. Raise ValueError if we
            can't understand the resulting array dtype.
        """
         
        #name, lcpl = self._e(name, lcpl=True)

        if isinstance(obj, HLObject):
            body = {'id': obj.id.uuid }
            req = "/groups/" + self.id.uuid + "/links/" + name
            self.PUT(req, body=body)
            
        elif isinstance(obj, SoftLink):
            body = {'h5path': obj.path }
            req = "/groups/" + self.id.uuid + "/links/" + name
            self.PUT(req, body=body)
            #self.id.links.create_soft(name, self._e(obj.path),
            #              lcpl=lcpl, lapl=self._lapl)

        elif isinstance(obj, ExternalLink):
            body = {'h5path': obj.path,
                    'h5domain': obj.filename }
            req = "/groups/" + self.id.uuid + "/links/" + name
            self.PUT(req, body=body)
            #self.id.links.create_external(name, self._e(obj.filename),
            #              self._e(obj.path), lcpl=lcpl, lapl=self._lapl)

        elif isinstance(obj, numpy.dtype):
            pass  #todo
            #htype = h5t.py_create(obj)
            #htype.commit(self.id, name, lcpl=lcpl)

        else:
            pass #todo
            #ds = self.create_dataset(None, data=obj, dtype=base.guess_dtype(obj))
            #h5o.link(ds.id, self.id, name, lcpl=lcpl)
        

    def __delitem__(self, name):
        """ Delete (unlink) an item from this group. """
        req = "/groups/" + self.id.uuid + "/links/" + name
        self.DELETE(req)
        #self.id.unlink(self._e(name))

    def __len__(self):
        """ Number of members attached to this group """
        req = "/groups/" + self.id.uuid 
        rsp_json = self.GET(req)
        return rsp_json['linkCount'] 
        #return self.id.get_num_objs()

    def __iter__(self):
        """ Iterate over member names """
        req = "/groups/" + self.id.uuid + "/links"
        rsp_json = self.GET(req)
        links = rsp_json['links']
        for x in links:
            yield x['title']
        """
        for x in self.id.__iter__():
            yield self._d(x)
        """
        

    def __contains__(self, name):
        """ Test if a member name exists """
        req = "/groups/" + self.id.uuid + "/links/" + name
        contains = True
        try:
            rsp_json = self.GET(req)
        except IOError as ioe:
            contains = False
            
        return contains
        #return self._e(name) in self.id

    def copy(self, source, dest, name=None,
             shallow=False, expand_soft=False, expand_external=False,
             expand_refs=False, without_attrs=False):
        """Copy an object or group.

        The source can be a path, Group, Dataset, or Datatype object.  The
        destination can be either a path or a Group object.  The source and
        destinations need not be in the same file.

        If the source is a Group object, all objects contained in that group
        will be copied recursively.

        When the destination is a Group object, by default the target will
        be created in that group with its current name (basename of obj.name).
        You can override that by setting "name" to a string.

        There are various options which all default to "False":

         - shallow: copy only immediate members of a group.

         - expand_soft: expand soft links into new objects.

         - expand_external: expand external links into new objects.

         - expand_refs: copy objects that are pointed to by references.

         - without_attrs: copy object without copying attributes.

       Example:

        >>> f = File('myfile.hdf5')
        >>> f.listnames()
        ['MyGroup']
        >>> f.copy('MyGroup', 'MyCopy')
        >>> f.listnames()
        ['MyGroup', 'MyCopy']

        """
        pass
        """
        with phil:
            if isinstance(source, HLObject):
                source_path = '.'
            else:
                # Interpret source as a path relative to this group
                source_path = source
                source = self

            if isinstance(dest, Group):
                if name is not None:
                    dest_path = name
                else:
                    # copy source into dest group: dest_name/source_name
                    dest_path = pp.basename(h5i.get_name(source[source_path].id))

            elif isinstance(dest, HLObject):
                raise TypeError("Destination must be path or Group object")
            else:
                # Interpret destination as a path relative to this group
                dest_path = dest
                dest = self

            flags = 0
            if shallow:
                flags |= h5o.COPY_SHALLOW_HIERARCHY_FLAG
            if expand_soft:
                flags |= h5o.COPY_EXPAND_SOFT_LINK_FLAG
            if expand_external:
                flags |= h5o.COPY_EXPAND_EXT_LINK_FLAG
            if expand_refs:
                flags |= h5o.COPY_EXPAND_REFERENCE_FLAG
            if without_attrs:
                flags |= h5o.COPY_WITHOUT_ATTR_FLAG
            if flags:
                copypl = h5p.create(h5p.OBJECT_COPY)
                copypl.set_copy_object(flags)
            else:
                copypl = None

            h5o.copy(source.id, self._e(source_path), dest.id, self._e(dest_path),
                     copypl, base.dlcpl)
        """

    def move(self, source, dest):
        """ Move a link to a new location in the file.

        If "source" is a hard link, this effectively renames the object.  If
        "source" is a soft or external link, the link itself is moved, with its
        value unmodified.
        """
        pass
        """
        with phil:
            if source == dest:
                return
            self.id.links.move(self._e(source), self.id, self._e(dest),
                               lapl=self._lapl, lcpl=self._lcpl)
        """

    def visit(self, func):
        """ Recursively visit all names in this group and subgroups (HDF5 1.8).

        You supply a callable (function, method or callable object); it
        will be called exactly once for each link in this group and every
        group below it. Your callable must conform to the signature:

            func(<member name>) => <None or return value>

        Returning None continues iteration, returning anything else stops
        and immediately returns that value from the visit method.  No
        particular order of iteration within groups is guranteed.

        Example:

        >>> # List the entire contents of the file
        >>> f = File("foo.hdf5")
        >>> list_of_names = []
        >>> f.visit(list_of_names.append)
        """
        pass
        """
        with phil:
            def proxy(name):
                return func(self._d(name))
            return h5o.visit(self.id, proxy)
        """

    def visititems(self, func):
        """ Recursively visit names and objects in this group (HDF5 1.8).

        You supply a callable (function, method or callable object); it
        will be called exactly once for each link in this group and every
        group below it. Your callable must conform to the signature:

            func(<member name>, <object>) => <None or return value>

        Returning None continues iteration, returning anything else stops
        and immediately returns that value from the visit method.  No
        particular order of iteration within groups is guranteed.

        Example:

        # Get a list of all datasets in the file
        >>> mylist = []
        >>> def func(name, obj):
        ...     if isinstance(obj, Dataset):
        ...         mylist.append(name)
        ...
        >>> f = File('foo.hdf5')
        >>> f.visititems(func)
        """
        pass
        """
        with phil:
            def proxy(name):
                name = self._d(name)
                return func(name, self[name])
            return h5o.visit(self.id, proxy)
        """

    def __repr__(self):
        if not self:
            r = six.u("<Closed HDF5 group>")
        else:
            namestr = (
                six.u('"%s"') % self.name
            ) if self.name is not None else six.u("(anonymous)")
            r = six.u('<HDF5 group %s (%d members)>') % (namestr, len(self))

        if six.PY3:
            return r
        return r.encode('utf8')


class HardLink(object):

    """
        Represents a hard link in an HDF5 file.  Provided only so that
        Group.get works in a sensible way.  Has no other function.
    """

    pass


#TODO: implement equality testing for these
class SoftLink(object):

    """
        Represents a symbolic ("soft") link in an HDF5 file.  The path
        may be absolute or relative.  No checking is performed to ensure
        that the target actually exists.
    """

    @property
    def path(self):
        return self._path

    def __init__(self, path):
        self._path = str(path)

    def __repr__(self):
        return '<SoftLink to "%s">' % self.path


class ExternalLink(object):

    """
        Represents an HDF5 external link.  Paths may be absolute or relative.
        No checking is performed to ensure either the target or file exists.
    """

    @property
    def path(self):
        return self._path

    @property
    def filename(self):
        return self._filename

    def __init__(self, filename, path):
        self._filename = str(filename)
        self._path = str(path)

    def __repr__(self):
        return '<ExternalLink to "%s" in file "%s"' % (self.path, self.filename)
