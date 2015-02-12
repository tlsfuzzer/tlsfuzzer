# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details


class Fingerprint(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

class Scanner(object):
    def scan(self, ip=None, port=443):
        return Fingerprint(ip, port)

