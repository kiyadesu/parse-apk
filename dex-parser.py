#coding:utf-8
# from utils import read_file
# from ctypes import *
import struct

#import binascii
# class DexHeader(Structure):
#     _fields_ = [
#         ("magic", c_char * 8),
#         ("chec"kSum", c_char * 4),
#         ('signature', c_char * 20),
#         ('fileSize', c_char * 4),
#         ("headerSize", c_char * 4),
#         ("lin"kSize", c_char * 4),
#         ("endianTag", c_char * 4),
#         ("lin"kOff", c_char * 4),
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

    DexMapList = {
        "size": 0,
        "DexMapItem": []
    }

    # DexMapItem = {
    #     "type" : 0
    #     "unused" : 0
    #     "size"  : 0
    #     "offset" : 0
    # }

    DexMapItemCode = {
        0x0000 : "kDexTypeHeaderItem"               ,
        0x0001 : "kDexTypeStringIdItem"             ,
        0x0002 : "kDexTypeTypeIdItem"               ,
        0x0003 : "kDexTypeProtoIdItem"              ,
        0x0004 : "kDexTypeFieldIdItem"              ,
        0x0005 : "kDexTypeMethodIdItem"             ,
        0x0006 : "kDexTypeClassDefItem"             ,
        0x1000 : "kDexTypeMapList"                  ,
        0x1001 : "kDexTypeTypeList"                 ,
        0x1002 : "kDexTypeAnnotationSetRefList"     ,
        0x1003 : "kDexTypeAnnotationSetItem"        ,
        0x2000 : "kDexTypeClassDataItem"            ,
        0x2001 : "kDexTypeCodeItem"                 ,
        0x2002 : "kDexTypeStringDataItem"           ,
        0x2003 : "kDexTypeDebugInfoItem"            ,
        0x2004 : "kDexTypeAnnotationItem"           ,
        0x2005 : "kDexTypeEncodedArrayItem"         ,
        0x2006 : "kDexTypeAnnotationsDirectoryItem" ,
    }

    # DexStringItem = {
    #     'offset' : 0,
    #     'len' : 0,
    #     'content' : '',
    # }

    DexStrings = []


def parseHeader(f):
        header_data = f.read(0x70)

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


def parseMapList(f):
    f.seek(DexStruct.DexHeader['mapOff'])
    map_data = f.read()

    DexStruct.DexMapList['size'] = struct.unpack('H',map_data[:2])[0]

    curPos = 4
    for x in range(DexStruct.DexMapList['size']):
        tmpDexMapItem = {
            "type" : struct.unpack('H',map_data[curPos:curPos+2])[0],
            "unused" : 0,
            "size"  : struct.unpack('I',map_data[curPos+4:curPos+8])[0],
            "offset" : struct.unpack('I',map_data[curPos+8:curPos+12])[0] }
        curPos += 12
        DexStruct.DexMapList["DexMapItem"].append(tmpDexMapItem)


def readuleb128(f):
    num = struct.unpack('B',f.read(1))[0]     # 读第一字节
    if num > 0x7f :
        cur = struct.unpack('B',f.read(1))[0]     #读第二字节
        num = (num and 0x7f) or ((cur and 0x7f) << 7)
        if cur > 0x7f:
            cur = struct.unpack('B',f.read(1))[0]     #读第三字节
            num = num or ((cur and 0x7f) << 14)
            if cur > 0x7f:
                cur = struct.unpack('B',f.read(1))[0]     #读第四字节
                num = num or ((cur and 0x7f) << 21)
                if cur > 0x7f:
                    cur = struct.unpack('B',f.read(1))[0]     #读第五字节
                    num = num or ((cur and 0x7f) << 28)
    return num


def parseStrings(f):
    f.seek(DexStruct.DexHeader['stringIdsOff'])
    stringIds_data = f.read(4*DexStruct.DexHeader['stringIdsSize'])

    cur_pos = 0
    for i in range(DexStruct.DexHeader['stringIdsSize']):
        str_off =  struct.unpack('I',stringIds_data[cur_pos:cur_pos+4])[0]
        f.seek(str_off)
        str_len = readuleb128(f)
        str_content = f.read(str_len)
        cur_pos += 4
        tmpDexStringItem = {
            'offset' : str_off,
            'len' : str_len,
            'content' : str_content,
        }
        DexStruct.DexStrings.append(tmpDexStringItem)


def parseDex(f):
    parseHeader(f)
    # for x in DexStruct.DexHeader:
    #     print x, hex(DexStruct.DexHeader[x])

    # parseMapList(f)
    # l = len(DexStruct.DexMapList['DexMapItem'])
    # for i in range(l):
    #     print DexStruct.DexMapItemCode[DexStruct.DexMapList['DexMapItem'][i]['type']],
    #     print hex(DexStruct.DexMapList['DexMapItem'][i]['size']),
    #     print hex(DexStruct.DexMapList['DexMapItem'][i]['offset'])

    parseStrings(f)
    for x in DexStruct.DexStrings:
        print hex(x['offset']),x['content']

#*********************************************

if __name__ == '__main__':

    with open(r"classes.dex", 'rb') as f:
        parseDex(f)
