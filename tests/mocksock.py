# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

import socket
import errno
class MockSocket(socket.socket):
    def __init__(self, buf, maxRet=None, maxWrite=None, blockEveryOther=False):
        # current position in read buffer (buf)
        self.index = 0
        # read buffer
        self.buf = buf
        # write buffer (data sent from application, to be asserted by test)
        self.sent = []
        self.closed = False
        # maximum number of bytes that socket will read/return at a time
        self.maxRet = maxRet
        # maximum number of bytes that socket will write at a time
        self.maxWrite = maxWrite
        # make socket rise errno.EWOULDBLOCK every other read or write
        self.blockEveryOther = blockEveryOther
        # if next read will be blocked
        self.blockRead = False
        # if next write will be blocked
        self.blockWrite = False

    def __repr__(self):
        return "MockSocket(index={0}, buf={1!r}, sent={2!r})".format(
                self.index, self.buf, self.sent)

    def recv(self, size):
        if self.closed:
            raise ValueError("Read from closed socket")

        # simulate a socket with full buffers, make it rise "Would block"
        # every other call
        if self.blockEveryOther:
            if self.blockRead:
                self.blockRead = False
                raise socket.error(errno.EWOULDBLOCK)
            else:
                self.blockRead = True

        # return empty array if the caller asked for no data
        if size == 0:
            return bytearray(0)

        # limit returned data (if set)
        # this will cause the socket to return just maxRet bytes, even if it
        # has more in buf or was asked to return more in this call
        if self.maxRet is not None and self.maxRet < size:
            size = self.maxRet

        # don't allow reading past array end
        if len(self.buf[self.index:]) == 0:
            raise socket.error(errno.EWOULDBLOCK)
        # if asked for more than we have prepared, return just as much as we
        # have
        elif len(self.buf[self.index:]) < size:
            ret = self.buf[self.index:]
            self.index = len(self.buf)
            return ret
        # regular call, return as much as was asked for
        else:
            ret = self.buf[self.index:self.index+size]
            self.index+=size
            return ret

    def send(self, data):
        if self.closed:
            raise ValueError("Write to closed socket")

        # simulate a socket with full buffer, raise "Would Block" every other
        # call
        if self.blockEveryOther:
            if self.blockWrite:
                self.blockWrite = False
                raise socket.error(errno.EWOULDBLOCK)
            else:
                self.blockWrite = True

        # regular write, just append to list of performed writes
        if self.maxWrite is None or len(data) < self.maxWrite:
            self.sent.append(data)
            return len(data)

        # simulate a socket that won't write more data that it can
        # (e.g. because the simulated buffers are mostly full)
        self.sent.append(data[:self.maxWrite])
        return self.maxWrite

    def close(self):
        self.closed = True
