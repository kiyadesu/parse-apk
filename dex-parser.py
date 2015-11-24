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

    DexTypes = []

    # DexProtoItem = {
    #     'shortyDescription' : None,
    #     'returnType' : None,
    #     'parameters' :  [],
    # };

    DexProtos = []

    # DexFieldItem = {
    #     'class' : None,
    #     'type' : None,
    #     'name' : None,
    # }

    DexFields = []

    # DexMethodItem = {
    #     'class' : None,
    #     'proto' : None,
    #     'name' : None,
    # }

    DexMethods = []

    # DexClassDef = {
    #     'class' : class_name,
    #     'accessFlags' : class_accessflag,
    #     'superclass' : class_superclass,
    #     'interfaces' : class_interface,
    #     'sourceFile' : class_sourcefile,
    #     'annotations' : class_annotation,
    #     'classData' : class_classdata,
    #     'staticValue' : class_staticvalue,
    # }

    DexClassDefs = []

#-------------------------------

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

def parseTypes(f):
    '''
    此函数基于 parseStrings 函数的结果，调用前需先调用 parseStrings
    '''
    f.seek(DexStruct.DexHeader['typeIdsOff'])

    for i in range(DexStruct.DexHeader['typeIdsSize']):
        type_desc_id = struct.unpack('I',f.read(4))[0]
        DexStruct.DexTypes.append(DexStruct.DexStrings[type_desc_id])

def parseProtos(f):
    '''
    此函数基于 parseStrings 和 parseTypes 函数的结果
    '''

    cur_pos = 0
    for i in range(DexStruct.DexHeader['protoIdsSize']):
        f.seek(DexStruct.DexHeader['protoIdsOff'] + cur_pos)

        proto_shortyId = struct.unpack('I',f.read(4))[0]
        proto_returnTypeId = struct.unpack('I',f.read(4))[0]
        proto_paramtersOff = struct.unpack('I',f.read(4))[0]

        parameters = []
        if proto_paramtersOff > 0:  # 有参数再读取
            f.seek(proto_paramtersOff)
            param_size = struct.unpack('I',f.read(4))[0]

            for j in range(param_size):
                param_typeId = struct.unpack('H',f.read(2))[0]
                parameters.append(DexStruct.DexTypes[param_typeId]['content'])

        tmpDexProtoItem = {
            'shortyDescription' : DexStruct.DexStrings[proto_shortyId]['content'],
            'returnType' : DexStruct.DexTypes[proto_returnTypeId]['content'],
            'parameters' :  parameters,
        };
        DexStruct.DexProtos.append(tmpDexProtoItem)

        cur_pos += 12

def parseFields(f):
    '''
    此函数基于 parseStrings 和 parseTypes 函数的结果
    '''
    f.seek(DexStruct.DexHeader['fieldIdsOff'])

    for i in range(DexStruct.DexHeader['fieldIdsSize']):
        field_class = DexStruct.DexTypes[struct.unpack('H',f.read(2))[0]]['content']
        field_type = DexStruct.DexTypes[struct.unpack('H',f.read(2))[0]]['content']
        field_name = DexStruct.DexStrings[struct.unpack('I',f.read(4))[0]]['content']

        tmpDexFieldItem = {
            'class' : field_class,
            'Type' : field_type,
            'name' : field_name,
        }
        DexStruct.DexFields.append(tmpDexFieldItem)

def parseMethods(f):
    '''
    此函数基于 parseStrings、parseProtos 和 parseTypes 函数的结果
    '''

    f.seek(DexStruct.DexHeader['methodIdsOff'])

    for i in range(DexStruct.DexHeader['methodIdsSize']):
        method_class = DexStruct.DexTypes[struct.unpack('H',f.read(2))[0]]['content']
        method_proto = DexStruct.DexProtos[struct.unpack('H',f.read(2))[0]]
        method_name = DexStruct.DexStrings[struct.unpack('I',f.read(4))[0]]['content']

        tmpDexMethodItem = {
            'class' : method_class,
            'proto' : method_proto,
            'name' : method_name,
        }
        DexStruct.DexMethods.append(tmpDexMethodItem)


def parseClassdef_Name(f):
    return DexStruct.DexTypes[struct.unpack('I',f.read(4))[0]]['content']

def parseClassdef_Accessflag(f):
    return struct.unpack('I',f.read(4))[0]

def parseClassdef_Superclass(f):
    class_superclass_id = struct.unpack('I',f.read(4))[0]
    if class_superclass_id == -1:
        return None
    return DexStruct.DexTypes[class_superclass_id]['content']

def parseClassdef_Interface(f):
    interface_off = struct.unpack('I',f.read(4))[0]
    if interface_off == 0:
        return None

    f.seek(interface_off)
    type_list_size = struct.unpack('I',f.read(4))[0]
    type_list = []
    for i in range(type_list_size):
        type_id = struct.unpack('H',f.read(2))[0]
        type_list.append(DexStruct.DexTypes[type_id]['content'])
    return type_list

def parseClassdef_Sourcefile(f):
    class_sourcefile_id = struct.unpack('I',f.read(4))[0]
    if class_sourcefile_id == -1:
        return None
    return DexStruct.DexStrings[class_sourcefile_id]['content']

def parseClassdef_Annotations(f):
    annotations_directory_off = struct.unpack('I',f.read(4))[0]
    if annotations_directory_off == 0:
        return None

    #-----------
    f.seek(annotations_directory_off)
    class_Annotations_Off = struct.unpack('I',f.read(4))[0]
    field_size = struct.unpack('I',f.read(4))[0]
    method_size = struct.unpack('I',f.read(4))[0]
    parameter_size = struct.unpack('I',f.read(4))[0]
    #---------
    annotations_directory = None
    if class_Annotations_Off != 0:
        # f.seek(class_Annotations_Off)
        # annotation_set_item_size = struct.unpack('I',f.read(4))[0]
        # for i in range(annotation_set_item_size):
        #     item_visibility = struct.unpack('B',f.read(1))[0]
        #     item_annotation = struct.unpack('B',f.read(1))[0]
        pass    # 解码暂且略过
    #--------
    f.seek(annotations_directory_off+4*4)
    fieldAnnotation_list = []
    for i in range(field_size):
        field = DexStruct.DexFields[struct.unpack('I',f.read(4))[0]]
        field_annotation_off = struct.unpack('I',f.read(4))[0]
        fieldAnnotation_item = {
            'field' : field,
            'annotationsOff' : field_annotation_off,
        }
        fieldAnnotation_list.append(fieldAnnotation_item)
    #--------
    f.seek(annotations_directory_off+4*4+field_size*8)
    methodAnnotation_list = []
    for i in range(method_size):
        method= DexStruct.DexMethods[struct.unpack('I',f.read(4))[0]]
        method_annotation_off = struct.unpack('I',f.read(4))[0]
        methodAnnotation_item = {
            'method' : method,
            'annotationsOff' : method_annotation_off,
        }
        methodAnnotation_list.append(methodAnnotation_item)
    #--------
    f.seek(annotations_directory_off+4*4+field_size*8+method_size*8)
    parameterAnnotation_list = []
    for i in range(parameter_size):
        param_method = DexStruct.DexMethods[struct.unpack('I',f.read(4))[0]]
        param_annotation_off = struct.unpack('I',f.read(4))[0]
        parameterAnnotation_item = {
            'method' : param_method,
            'annotationsOff' : param_annotation_off,
        }
        parameterAnnotation_list.append(parameterAnnotation_item)

    tmpDexAnnotationsDirectoryItem = {
        'classAnnotations' : annotations_directory,
        'fieldSize' : field_size,
        'methodSize' : method_size,
        'parameterSize' : parameter_size,
        'fieldAnnotation' : fieldAnnotation_list,
        'methodAnnotation' : methodAnnotation_list,
        'parameterAnnotaions' : parameterAnnotation_list,
    }
    return tmpDexAnnotationsDirectoryItem

def parseClassdef_ClassData(f):
    class_data_off = struct.unpack('I',f.read(4))[0]
    if class_data_off == 0:
        return None

    f.seek(class_data_off)

    #-----
    header = {
        'staticFieldsSize' : readuleb128(f),
        'instanceFieldsSize' :  readuleb128(f),
        'directMethodsSize' : readuleb128(f),
        'virtualMethodsSize' : readuleb128(f),
    }
    #-----
    staticFields = []
    if header['staticFieldsSize'] != 0:
        for i in range(header['staticFieldsSize']):
            tmpstaticFields = {
                'field' : DexStruct.DexFields[readuleb128(f)],
                'accessFlags' : readuleb128(f)
            }
            staticFields.append(tmpstaticFields)
    #-----------
    instanceFields = []
    if header['instanceFieldsSize'] != 0:
        for i in range(header['instanceFieldsSize']):
            tmpinstanceFields = {
                'field' : DexStruct.DexFields[readuleb128(f)],
                'accessFlags' : readuleb128(f)
            }
            instanceFields.append(tmpinstanceFields)
    #-----
    directMethods = []
    if header['directMethodsSize'] != 0:
        for i in range(header['directMethodsSize']):
            tmpdirectMethods = {
                'method' : DexStruct.DexMethods[readuleb128(f)],
                'accessFlags' : readuleb128(f),
                'codeOff': readuleb128(f),
                ####### dexcode 还没解析
            }
            directMethods.append(tmpdirectMethods)
    #-----
    virtualMethods = []
    if header['virtualMethodsSize'] != 0:
        for i in range(header['virtualMethodsSize']):
            tmpvirtualMethods = {
                'method' : DexStruct.DexMethods[readuleb128(f)],
                'accessFlags' : readuleb128(f),
                'codeOff' : readuleb128(f)
                ####### dexcode 还没解析
            }
            virtualMethods.append(tmpvirtualMethods)

    DexClassData = {
        'DexClassDataHeader' : header,
        'staticFields' : staticFields,
        'instanceFields' : instanceFields,
        'directMethods' : directMethods,
        'virtualMethods' : virtualMethods,
    }

    return DexClassData

def parseClassdef_StaticValue(f):
    staticvalue_off = struct.unpack('I',f.read(4))[0]
    if staticvalue_off == 0:
        return None
    return None ## 还没解析 encoded value

def parseClassdefs(f):
    '''
    此函数基于之前所有的函数结果
    '''

    for i in range(DexStruct.DexHeader['classDefsSize']):
        item_off = i*4*8 + DexStruct.DexHeader['classDefsOff']
        f.seek(item_off)

        class_name = parseClassdef_Name(f)
        class_accessflag = parseClassdef_Accessflag(f)
        class_superclass = parseClassdef_Superclass(f)

        class_interface = parseClassdef_Interface(f)
        f.seek(item_off+4*4)

        class_sourcefile = parseClassdef_Sourcefile(f)
        class_annotation = parseClassdef_Annotations(f)
        f.seek(item_off+4*6)

        class_classdata = parseClassdef_ClassData(f)

        f.seek(item_off+4*7)
        class_staticvalue = parseClassdef_StaticValue(f)

        tmpDexClassDef = {
            'class' : class_name,
            'accessFlags' : class_accessflag,
            'superclass' : class_superclass,
            'interfaces' : class_interface,
            'sourceFile' : class_sourcefile,
            'annotations' : class_annotation,
            'classData' : class_classdata,
            'staticValue' : class_staticvalue,
        }
        DexStruct.DexClassDefs.append(tmpDexClassDef)

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
    # for x in DexStruct.DexStrings:
    #     print hex(x['offset']),x['content']

    parseTypes(f)
    # for x in DexStruct.DexTypes:
    #     print hex(x['offset']),x['content']

    parseProtos(f)
    # for x in DexStruct.DexProtos:
    #     print x['returnType'],
    #     print '~~~~~',
    #     print x['parameters']

    # parseFields(f)
    # for x in DexStruct.DexFields:
    #     print x

    parseMethods(f)
    # for x in DexStruct.DexMethods:
    #     print x

    parseClassdefs(f)



#*********************************************

if __name__ == '__main__':

    # with open(r"/media/d/dafuweng/ditiepaoku/classes.dex", 'rb') as f:
    with open(r"/home/hanks/kiya/parse-apk/classes.dex", 'rb') as f:
        parseDex(f)
