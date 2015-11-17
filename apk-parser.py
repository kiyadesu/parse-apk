
#coding:utf-8

from utils import read_file
from zipfile import ZipFile
from StringIO import StringIO
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
    apk = apkParser('LightningBackup.apk')
    apk.parse()
