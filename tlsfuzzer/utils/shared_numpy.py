import sys
try:
    from multiprocessing import shared_memory
except ImportError:
    # the SharedMemmap will work with verions of python that don't have
    # shared_memory
    pass
import numpy as np


class SharedNDarray(object):
    """
    A Numpy array that is backed by shared_memory.

    (Needs at least Python 3.8 to work)

    A wrapper (proxy) for numpy array so that it can be cheaply passed between
    the processes.

    It provides proxy methods for the most common operations (iter, len,
    getitem).

    The original shared memory object should outlive all the copies, and
    when it's no longer needed, the backing shared_memory object needs to be
    first ``.close()``'ed and then ``.unlink()``'ed.
    For better determinism, the copies should be ``del``-eted so that they
    close the used shared memory.

    :param value: the actual numpy ndarray
    :param shm: the backing shared memory object.
    """
    def __init__(self, data):
        """Init the object with a numpy array.

        :param data: a numpy array object
        """
        shm = shared_memory.SharedMemory(create=True, size=data.nbytes)
        self.shm = shm
        copy = np.ndarray(data.shape, dtype=data.dtype, buffer=shm.buf)
        self._shape = data.shape
        self._dtype = data.dtype
        copy[:] = data[:]
        self.value = copy
        self.copy = False

    def __getitem__(self, key):
        return self.value[key]

    def __iter__(self):
        return self.value.__iter__()

    def __len__(self):
        return self.value.__len__()

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['value']  # not pickleable
        del state['shm']  # resource tracking is messing stuff up
        state['_name'] = self.shm.name
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        if sys.version_info < (3, 13):
            self.shm = shared_memory.SharedMemory(state['_name'])
        else:
            # prevent Resource Manager from complaining about a memory
            # managed by another process
            # see also https://github.com/python/cpython/issues/82300
            self.shm = shared_memory.SharedMemory(state['_name'], track=False)
        del self._name
        self.copy = True
        value = np.ndarray(self._shape, dtype=self._dtype, buffer=self.shm.buf)
        self.value = value

    def __del__(self):
        # we perform automated cleanup only for the copy, the original
        # needs to be cleaned-up explicitly
        if self.copy:
            del self.value
            self.shm.close()


class SharedMemmap(object):
    """A numpy memmap that supports efficient pickling

    As the numpy memmap doesn't perform efficient pickling (serialises the
    data, not the file access), it wraps it (proxies) around it to provide
    for easy passing between processes.

    Note, that while the original object will provide efficient pickling,
    subscripting it (i.e.  ``object[start:stop]``) **will not**. You can
    partially work-around it by using the ``column`` parameter for the
    constructor, but in general it's necessary to pass in the whole object
    and the slice as separate arguments to the worker threads.

    :param str filename: The name of the file, see ``numpy.memmap``
    :param dtype: ctype description of the data, see ``numpy.memmap``
    :param mode: file access mode, see ``numpy.memmap``
    :param offset: file offset, see ``numpy.memmap``
    :param shape: data shape for multi-dimensional arrays,
        see ``numpy.memmmap``
    :param order: on-disk data ordering for multi-dimensional arrays, see
        ``numpy.memmap``
    :param column: the key (column) to extract from the data file right after
        opening and before returning from the constructor
    """
    def __init__(self, filename, dtype, mode="r+", offset=0, shape=None,
                 order="C", column=None):
        self.filename = filename
        self.dtype = dtype
        self.mode = mode
        self.offset = offset
        self.shape = shape
        self.order = order
        self.column = column
        self.value = None
        self._open()

    def __getitem__(self, key):
        return self.value[key]

    def __iter__(self):
        return self.value.__iter__()

    def __len__(self):
        return self.value.__len__()

    def _open(self):
        self.value = np.memmap(
            self.filename, self.dtype, self.mode, self.offset, self.shape,
            self.order)
        if self.column:
            self.value = self.value[self.column]

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['value']  # not pickleable
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._open()
