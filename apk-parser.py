
#coding:utf-8

from utils import read_file
from zipfile import ZipFile
from StringIO import StringIO
import sys
import os.path

class apkParser():
    def __init__(self, apk_path):
        self.apk_path = apk_path

    def parse(self):
        self._raw_data = read_file(self.apk_path)
        self.file_size = len(self._raw_data)
        self.zip = ZipFile(StringIO(self._raw_data))
        print self.file_size/1024, 'kb'
        for x in self.zip.namelist():
            if x == 'AndroidManifest.xml':
                print self.zip.read(x)


    def output(self):
        print self.parse()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        apk_path = sys.argv[1]
        apk = apkParser(apk_path)
        apk.parse()
    else:
        print 'error: must be like "python parse-apk.py ./test.apk"'
