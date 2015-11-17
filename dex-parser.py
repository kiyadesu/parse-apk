from utils import read_file
from ctypes import *
import struct

#import binascii
# class DexHeader(Structure):
#     _fields_ = [
#         ("magic", c_char * 8),
#         ("checkSum", c_char * 4),
#         ('signature', c_char * 20),
#         ('fileSize', c_char * 4),
#         ("headerSize", c_char * 4),
#         ("linkSize", c_char * 4),
#         ("endianTag", c_char * 4),
#         ("linkOff", c_char * 4),
#         ("mapOff", c_char * 4),
#         ("stringIdsSize", c_char * 4),
#         ("stringIdsOff", c_char * 4),
#         ("typeIdsSize", c_char * 4),
#         ("typeIdsOff", c_char * 4),
#         ("protoIdsSize", c_char * 4),
#         ("protoIdsOff", c_char * 4),
#         ("fieldIdsSize", c_char * 4),
#         ("fieldIdsOff", c_char * 4),
#         ("methodIdsSize", c_char * 4),
#         ("methodIdsOff", c_char * 4),
#         ("classDefsSize", c_char * 4),
#         ("classDefsOff", c_char * 4),
#         ("dataSize", c_char * 4),
#         ("dataOff", c_char * 4),
#     ]
# 8 + 4 + x + 20*4 = 112
#dex_ascii_data = binascii.b2a_hex(header_data)
#print dex_ascii_data
#print '------'
# dex_ascii_list = [dex_ascii_data[i:i+8] for i in range(64,224,8)]
# dex_ascii_list.insert(0,dex_ascii_data[24:64])
# dex_ascii_list.insert(0,dex_ascii_data[16:24])
# dex_ascii_list.insert(0,dex_ascii_data[:16])
#print dex_ascii_list
#header = DexHeader(*dex_ascii_list)

class DexStruct(object):
    DexHeader = {
          "magic": 0,
          "checkSum": 0,
          'signature': 0,
          'fileSize': 0,
          "headerSize": 0,
          "endianTag": 0,
          "linkSize": 0,
          "linkOff": 0,
          "mapOff": 0,
          "stringIdsSize": 0,
          "stringIdsOff": 0,
          "typeIdsSize": 0,
          "typeIdsOff": 0,
          "protoIdsSize": 0,
          "protoIdsOff": 0,
          "fieldIdsSize": 0,
          "fieldIdsOff": 0,
          "methodIdsSize": 0,
          "methodIdsOff": 0,
          "classDefsSize": 0,
          "classDefsOff": 0,
          "dataSize": 0,
          "dataOff": 0,   }


def parseHeader(header_data):

        header_list = [header_data[i:i+4] for i in range(32,112,4)]
        header_list.insert(0,header_data[12:32])
        header_list.insert(0,header_data[8:12])
        header_list.insert(0,header_data[:8])

        DexStruct.DexHeader['magic'] = struct.unpack('8s',header_list[0])[0]
        if DexStruct.DexHeader['magic'] != "dex\n035\0":
            print 'invalid dex file.'
            exit(-1)
        DexStruct.DexHeader['checkSum'] = struct.unpack('I',header_list[1])[0]
        DexStruct.DexHeader['signature'] = struct.unpack('20s',header_list[2])[0]
        DexStruct.DexHeader['fileSize'] = struct.unpack('I',header_list[3])[0]
        DexStruct.DexHeader['headerSize'] = struct.unpack('I',header_list[4])[0]
        DexStruct.DexHeader['endianTag'] = struct.unpack('I',header_list[5])[0]
        DexStruct.DexHeader['linkSize'] = struct.unpack('I',header_list[6])[0]
        DexStruct.DexHeader['linkOff'] = struct.unpack('I',header_list[7])[0]
        DexStruct.DexHeader['mapOff'] = struct.unpack('I',header_list[8])[0]
        DexStruct.DexHeader['stringIdsSize'] = struct.unpack('I',header_list[9])[0]
        DexStruct.DexHeader['stringIdsOff'] = struct.unpack('I',header_list[10])[0]
        DexStruct.DexHeader['typeIdsSize'] = struct.unpack('I',header_list[11])[0]
        DexStruct.DexHeader['typeIdsOff'] = struct.unpack('I',header_list[12])[0]
        DexStruct.DexHeader['protoIdsSize'] = struct.unpack('I',header_list[13])[0]
        DexStruct.DexHeader['protoIdsOff'] = struct.unpack('I',header_list[14])[0]
        DexStruct.DexHeader['fieldIdsSize'] = struct.unpack('I',header_list[15])[0]
        DexStruct.DexHeader['fieldIdsOff'] = struct.unpack('I',header_list[16])[0]
        DexStruct.DexHeader['methodIdsSize'] = struct.unpack('I',header_list[17])[0]
        DexStruct.DexHeader['methodIdsOff'] = struct.unpack('I',header_list[18])[0]
        DexStruct.DexHeader['classDefsSize'] = struct.unpack('I',header_list[19])[0]
        DexStruct.DexHeader['classDefsOff'] = struct.unpack('I',header_list[20])[0]
        DexStruct.DexHeader['dataSize'] = struct.unpack('I',header_list[21])[0]
        DexStruct.DexHeader['dataOff'] = struct.unpack('I',header_list[22])[0]


if __name__ == '__main__':

    with open("classes.dex", 'rb') as f:
        parseHeader(f.read(0x70))
        for x in DexStruct.DexHeader:
            print x, hex(DexStruct.DexHeader[x])
        print f.tell()
