import struct
import zlib
import analysis
import os
from analysis.node import Node, NodeType
from common.logger import Logger
from .ufs import Endianness, SuperBlock, endianness
from Cryptodome.Cipher import AES

import disklib

def round_to_multiple(number, multiple):
    return multiple * round(number / multiple)

def bytes_to_string(data, start_offset=0):
    s = bytearray()
    for i in range(start_offset, len(data)):
        c = data[i]
        if (c == 0):
            break
        s.append(c)
    try:  
        return s.decode('ascii')
    except UnicodeDecodeError:
        return ''

class FileCarver:
    def __init__(self, stream, offset):
        self._stream = stream
        self.offset = offset
        self.size = 0
        self.name = ''
        self.extension = ''
        self._stream.seek(self.offset)
        self.initialization()

    def seek(self, offset, whence=0):
        if whence != 1:
            offset += self.offset
        self._stream.seek(offset, whence)
    
    def tell(self):
        return self._stream.tell() - self.offset

    def read(self, size):
        return self._stream.read(size)
    
    def u8be(self):
        return struct.unpack(">B", self.read(1))[0]

    def u16be(self):
        return struct.unpack(">H", self.read(2))[0]

    def u32be(self):
        return struct.unpack(">L", self.read(4))[0]

    def u64be(self):
        return struct.unpack(">Q", self.read(8))[0]

    def floatbe(self):
        return struct.unpack(">f", self.read(4))[0]

    def doublebe(self):
        return struct.unpack(">d", self.read(8))[0]

    def u8le(self):
        return struct.unpack("<B", self.read(1))[0]

    def u16le(self):
        return struct.unpack("<H", self.read(2))[0]

    def u32le(self):
        return struct.unpack("<L", self.read(4))[0]

    def u64le(self):
        return struct.unpack("<Q", self.read(8))[0]

    def floatle(self):
        return struct.unpack("<f", self.read(4))[0]

    def doublele(self):
        return struct.unpack("<d", self.read(8))[0]
    
    def read_cstring(self, length=0):
        s = ''
        while True:
            if len(s) > length and length != 0:
                return s
            c = self.read(1)
            if c == b'\x00':
                break
            try:
                s1 = c.decode('ascii')
            except UnicodeDecodeError:
                break
            s += s1
        self.seek(-1,1)
        return s

    def initialization(self):
        pass

    def test(self):
        pass

    def parse(self):
        pass
    


class JPEGCarver(FileCarver):
    def initialization(self):
        self.extension='.jpeg'
        
    def test(self):
        magic = self.read(3)
        if magic == 0xFFD8FF:
            magic2 = self.read(1)
            if magic2 == 0xDB:
                return True
            if magic2 == 0xE0:
                return True
            if magic2 == 0xEE:
                return True
            if magic2 == 0xE1:
                return True
        return False


class ARCCarver(FileCarver):
    def initialization(self):
        self.extension='.arc'
        
    def test(self):
        magic = self.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.read(4)
            if magic2 == b"\0CRA":
                return True
        return False


class PAMCarver(FileCarver):
    def initialization(self):
        self.extension='.pam'
        
    def test(self):
        magic = self.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.read(3)
            if magic2 == b"PAM":
                return True
        return False


class AT3Carver(FileCarver):
    def initialization(self):
        self.extension='.at3'
        
    def test(self):
        magic = self.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.read(4)
            if magic2 == b"RIFF":
                return True
        return False


class TEXCarver(FileCarver):
    def initialization(self):
        self.extension='.tex'
        
    def test(self):
        magic = self.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.read(4)
            if magic2 == b"\0XET":
                return True
        return False


class SQTRCarver(FileCarver):
    def initialization(self):
        self.extension='.sqtr'
        
    def test(self):
        magic = self.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.read(4)
            if magic2 == b"RQTS":
                return True
        return False


class AVICarver(FileCarver):
    def initialization(self):
        self.extension='.avi'
        
    def test(self):
        magic = self.read(4)
        if magic == b"RIFF":
            self.seek(8)
            magic2 = self.read(4)
            if magic2 == b"AVI\x20":
                return True
        return False


class WaveCarver(FileCarver):
    def initialization(self):
        self.extension='.wav'
        
    def test(self):
        magic = self.read(4)
        if magic == b"RIFF":
            self.seek(8)
            magic2 = self.read(4)
            if magic2 == b"WAVE":
                return True
        return False


class MPEGCarver(FileCarver):
    def initialization(self):
        self.extension='.zlib'
        
    def test(self):
        magic = self.read(4)
        return magic == 0x4C5A4950


class LZipCarver(FileCarver):
    def initialization(self):
        self.extension='.lz'
        
    def test(self):
        magic = self.read(4)
        return magic == 0x4C5A4950


class ZipCarver(FileCarver):
    def initialization(self):
        self.extension='.zip'

    def test(self):
        magic = self.read(3)
        return magic == 0x504B03


class TarGZCarver(FileCarver):
    def initialization(self):
        self.extension='.tar'
        
    def test(self):
        magic = self.read(2)
        magic1 = 0x1F9D
        magic2 = 0x1FA0
        magic3 = 0x1F8B
        if magic3 == magic:
            self.extension = '.gz'
        return magic == magic1 or magic == magic2 or magic == magic3


class RIFACarver(FileCarver):
    def initialization(self):
        self.extension='.rif'

    def test(self):
        magic = self.read(4)
        return magic == b"rifa"

    def parse(self):
        _size = 0x400
        while True:
            self.seek(0x400,1)
            magic = self.read(4)
            if magic == b'ROF\0':
                _size += 0x400
            else:
                self.size = _size
                return


class RIFCarver(FileCarver):
    def initialization(self):
        self.extension='.rif'

    def test(self):
        magic = self.read(4)
        return magic == b"RIF\0"

    def parse(self):
        self.size = 0x400


class RIDXCarver(FileCarver):
    def initialization(self):
        self.extension='.idx'

    def test(self):
        magic = self.read(4)
        return magic == b"xdir"

    def parse(self):
        self.seek(0x04)
        rif_cnt = self.u32le()
        self.size = (rif_cnt * 48) + 32


class PBMCarver(FileCarver):
    def initialization(self):
        self.extension='.pbm'

    def test(self):
        magic = self.read(4)
        return magic == b"pdbm"


class PKGCarver(FileCarver):
    def initialization(self):
        self.extension='.pkg'
    
    def test(self):
        magic = self.read(4)
        return magic == b"\x7FPKG"

    def parse(self):
        self.seek(0x18)
        self.size = self.u64be()
        self.seek(0x30)
        self.name = self.read_cstring()


class SelfCarver(FileCarver):
    def initialization(self):
        self.extension='.self'
        
    def test(self):
        magic = self.read(4)
        return magic == b"SCE\0"

    def parse(self):
        self.seek(0x10)
        self.size = self.u64be() + self.u64be()
        self.extension = ".self"


class ElfCarver(FileCarver):
    def initialization(self):
        self.extension='.elf'

    def test(self):
        magic = self.read(4)
        return magic == b"\x7FELF"


class PUPCarver(FileCarver):
    def initialization(self):
        self.extension='.pup'
    
    def test(self):
        magic = self.read(8)
        return magic == b"SCEUF\0\0"


class SFOCarver(FileCarver):
    def initialization(self):
        self.extension='.sfo'

    def test(self):
        magic = self.read(4)
        return magic == b"\0PSF"
    
    def parse(self):
        self.seek(8)
        key_table_start = self.u32le()
        data_table_start = self.u32le()
        num_ents = self.u32le()

        last_data_offset = 0
        last_data_size = 0
        for x in range(num_ents):
            self.seek(4, 1)
            data_size = self.u32le()
            self.seek(4, 1)
            data_offset = self.u32le()
            if data_offset > last_data_offset:
                last_data_size = data_size
                last_data_offset = data_offset
        self.size = data_table_start + last_data_offset + last_data_size


class NPDCarver(FileCarver):
    def test(self):
        magic = self.read(4)
        if magic == b'NPD\0':
            self.seek(0x90)
            npdtype = self.u8be()
            if (npdtype & 0xf) == 0x0:
                self.extension = ".edat"
            elif (npdtype & 0xf) == 0x1:
                self.extension = ".sdat"
            else:
                self.extension = ".npd"

    def parse(self):
        self.seek(0x98)
        self.size = self.u64be()


class TRPCarver(FileCarver):
    SIZEOF_HEADER = 0x40
    def initialization(self):
        self.extension='.trp'
    
    def test(self):
        magic = self.u32be()
        return magic == 0xDCA24D00

    def parse(self):
        self.seek(8)
        self.size = self.u64be() + TRPCarver.SIZEOF_HEADER


class PNGCarver(FileCarver):
    def initialization(self):
        self.extension='.png'

    def test(self):
        magic = self.read(8)
        if magic == b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A':
            return True
        return False

    def parse(self):
        self.extension = ".png"
        self.seek(8)
        while True:
            length = self.u32be()
            ctype = self.read(4)
            cdata = self.read(length)
            ccrc = self.u32be()
            crc = zlib.crc32(ctype + cdata) & 0xffffffff
            if crc != ccrc:
                Logger.log("ERROR: Invalid CRC!"),
                break
            if ctype == "IEND":
                break
        self.size = self.tell()


class BMPCarver(FileCarver):
    def initialization(self):
        self.extension='.bmp'

    def test(self):
        magic = self.read(2)
        size = self.u32le()
        if magic == b'BM' and size < 16000000 : # anything over 16MB probably means this is a false positive
            return True
        return False


class HKXCarver(FileCarver):
    def initialization(self):
        self.extension='.hkx'
    
    def test(self):
        magic = self.read(8)
        return magic == b'\x57\xE0\xE0\x57\x10\xC0\xC0\x10'

    def parse(self):
        self.seek(0xB4)
        offset = self.u32be()
        self.seek(0xCC)
        size = self.u32be()
        self.size = offset + size


class BIKCarver(FileCarver):
    def initialization(self):
        self.extension='.bik'
    
    def test(self):
        magic = self.read(3)
        return magic == b'BIK'

    def parse(self):
        self.seek(4)
        self.size = self.u32le() + 8


class PCKCarver(FileCarver):
    def initialization(self):
        self.extension='.pck'
    
    def test(self):
        magic = self.read(4)
        return magic == b'AKPK'


class UnrealArchiveCarver(FileCarver):
    def initialization(self):
        self.extension='.xxx'
    
    def test(self):
        magic = self.read(4)
        return magic == b'\x9E\x2A\x83\xC1'

    def parse(self):
        # Rather than parsing a complex Unreal Archive file just look for the padding at the end
        endFound = False
        for i in range(0, 0x8000000, 48):
            self.seek(i)
            # if you hit what might be padding
            if self.read(48) == b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0':
                # go to where the padding starts
                self.seek(-48, 1)
                # align
                self.seek((self.tell() + 0x8000) & ~(0x8000 - 1))
                # are the last 16 bytes padding?
                self.seek(-16, 1)
                if self.read(16) == b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0':
                    endFound = True
                    break

        if endFound == False:
            Logger.log("...End of archive not found")
            return

        self.size = self.tell()



last_found_utoc = None
class UnrealTOCCarver(FileCarver):
    def initialization(self):
        self.name='UnkownTOC'
        self.extension='.txt'

    def test(self):
        global last_found_utoc
        if last_found_utoc:
            if last_found_utoc.offset + last_found_utoc.size > self.offset:
                return False
        magic = self.read_cstring(64)
        magic = magic.lower()
        if 'cookedps3' in magic or 'coalesced' in magic:
            self.parse()
            # Minimum size
            if self.size < 0x100:
                return False
            last_found_utoc = self
            return True
        return False
    
    def parse(self):
        self.read_cstring()
        self.size = self.tell()

##
##  RPF FILES
##
class RPFCommon():
    RPFVERSIONS = {}
    ## RPFVERSIONS[b'\x30'] = 'Rockstar Games Presents Table Tennis'
    ## RPFVERSIONS[b'\x32'] = 'Grand Theft Auto IV'
    RPFVERSIONS[b'\x33'] = 'Grand Theft Auto IV Audio OR Midnight Club: Los Angeles'
    RPFVERSIONS[b'\x34'] = 'Max Payne 3'
    RPFVERSIONS[b'\x36'] = 'Red Dead Redemption'
    RPFVERSIONS[b'\x37'] = 'Grand Theft Auto V'
    RPFVERSIONS[b'\x38'] = 'Red Dead Redemption 2'

    ENCRYPTION_TYPE = {}
    ENCRYPTION_TYPE[0] = 'None'
    ENCRYPTION_TYPE[0x4E45504F] = 'Open' #OpenIV
    ENCRYPTION_TYPE[0x0FFFFFF8] = 'AES'
    ENCRYPTION_TYPE[0x0FEFFFFF] = 'NG'

    KEYS_360 = {}
    KEYS_360[b'\x33'] = 0xAF7CD2E9FAAA45FD9728AC247DD0CE5ED6E4A182FFE241DB8FF0703B629C478
    KEYS_360[b'\x34'] = 0x95FC19EE3200C604A070FE8E6858DB768811A302110905A48D39EDAE4332545A
    KEYS_360[b'\x36'] = 0xB762DFB6E2B2C6DEAF722A32D2FB6F0C98A3217462C9C4EDADAA2ED0DDF92F10
    KEYS_360[b'\x37'] = 0xA1E729395D8AD10B9B7BD011D528693D96E22BD6A28AABAEB4A69AC6F973627F

    KEYS_PS3 = {}
    KEYS_PS3[b'\x33'] = 0xAF7CD2E9FAAA45FD9728AC247DD0CE5ED6E4A182FFE241DB8FF0703B629C478
    KEYS_PS3[b'\x34'] = 0x95FC19EE3200C604A070FE8E6858DB768811A302110905A48D39EDAE4332545A
    KEYS_PS3[b'\x36'] = 0xB762DFB6E2B2C6DEAF722A32D2FB6F0C98A3217462C9C4EDADAA2ED0DDF92F10
    KEYS_PS3[b'\x37'] = 0x85136E1E37FCBC4594E7F7BC5F185200B32A67308CC1B833B32A67308CC1B833

    '''
    Key at 0x015119A4 - 0x015119C3  in EBOOT for Max Payne
    Red Dead Redemption PS3/X360: B762DFB6E2B2C6DEAF722A32D2FB6F0C98A3217462C9C4EDADAA2ED0DDF92F10
    Max Payne 3 PS3/X360: 95FC19EE3200C604A070FE8E6858DB768811A302110905A48D39EDAE4332545A
    Midnight Club PS3/X360: AF7CD2E9FAAA45FD9728AC247DD0CE5ED6E4A182FFE241DB8FF0703B629C4785
    '''

class RPFType:
    FILE = 0
    DIRECTORY = 1
    RESOURCE = 2
    BINARY = 3
    UNKNOWN = 4


# RPF 3
class RPF3Carver(FileCarver):
    def test(self):
        magic = self.read(4)
        if magic == b'\x52\x50\x46\x33':
            return True
        return False

    def parse(self):
        self.extension = ".rpf"


# RPF 4
class RPF4Carver(FileCarver):
    def test(self):
        magic = self.read(4)
        if magic == b'\x52\x50\x46\x34':
            return True
        return False

    def parse(self):
        self.extension = ".rpf"


# RPF 6
class RPF6TOCEntry(object):

    name_offset = 0
    size = 0
    uncompressed_size = 0
    file_offset = 0
    filetype = None
    name = ''

    def print_entry(self):
        Logger.log("Name: "+self.name)
        Logger.log("|- Name Offset: 0x"+format(self.name_offset,"X"))
        Logger.log("|- Size: 0x"+format(self.size,"X"))
        Logger.log("|- Uncompressed Size: 0x"+format(self.uncompressed_size,"X"))
        Logger.log("|- File Offset: 0x"+format(self.file_offset,"X"))

class RPF6Carver(FileCarver):
    rpf = RPFCommon()
    endianness = 'big'
    encryption = 0
    version = b'\x36'

    def test(self):
        magic = self.read(4)
        if magic == b'\x52\x50\x46\x36':
            return True
        return False
    
    def parse(self):
        self.extension = ".rpf"
        self.seek(4)
        entry_count = self.u32be()
        toc_size = entry_count * 20

        self.seek(0x10)

        # Decrypt the TOC
        #
        entries_data = self.read( round_to_multiple(toc_size, 16) )
        
        if(self.encryption == 'AES'):
            Logger.log("AES Encryption...")
            decryptor = AES.new(self.rpf.KEYS_PS3[self.version].to_bytes(32, self.endianness), AES.MODE_ECB) #  Hardcoded for ps3 right now
            decryptor.block_size = 128
            entries_data = decryptor.decrypt(entries_data)

        # Parse the TOC
        #
        Logger.log("Reading TOC Entries...")
        toc = self.parse_toc(bytearray(entries_data))
        for entry in toc:
            entry:RPF6TOCEntry
            # Add size of the entries to the length
            if(entry.size == 0):
                self.size += entry.uncompressed_size
            else:
                self.size += entry.size
        
        # Add header size to the length
        self.size += 0x10 + toc_size #+ toc_names_length

        # Align to 0x800
        self.size = ((self.size + 0x800) & ~(0x800 - 1))

    def parse_toc(self, toc_decrypted):
        toc = []
        for i in range(0, len(toc_decrypted), 20):
            
            entry = RPF7TOCEntry()
            toc.append(entry)

            ident = toc_decrypted[i+8:i+9]

            if ident == 128:
                entry.filetype = RPFType.DIRECTORY
            else:
                entry.filetype = entry.filetype = RPFType.FILE
                entry.name_offset = toc_decrypted[i:i+4]
                entry.size = toc_decrypted[i+4:i+8]
                entry.file_offset = toc_decrypted[i+8:i+12]
                flags1 = toc_decrypted[i+12:i+16]
                flags2 = toc_decrypted[i+16:i+20]
                is_resource_file = (flags1 & 0x80000000) == 0x80000000

                if is_resource_file:
                    entry.filetype = RPFType.RESOURCE

        return toc



# RPF 7
class RPF7TOCEntry(object):
    FILETYPES = {}
    FILETYPES['Unknown'] = 0
    FILETYPES['Directory'] = 1
    FILETYPES['Resource'] = 2
    FILETYPES['Binary'] = 3

    name_offset = 0
    size = 0
    uncompressed_size = 0
    file_offset = 0
    filetype = FILETYPES['Unknown']
    name = ''

    def print_entry(self):
        Logger.log("Name: "+self.name)
        Logger.log("|- Name Offset: 0x"+format(self.name_offset,"X"))
        Logger.log("|- Size: 0x"+format(self.size,"X"))
        Logger.log("|- Uncompressed Size: 0x"+format(self.uncompressed_size,"X"))
        Logger.log("|- File Offset: 0x"+format(self.file_offset,"X"))


class RPF7Carver(FileCarver):

    rpf = RPFCommon()
    endianness = 'big'
    encryption = 0
    version = b'\x37'

    def test(self):
        magic = self.read(4)
        if magic == b'\x52\x50\x46\x37':
            return True
        return False

    def parse(self):
        self.extension = ".rpf"
        self.seek(4) # seek past the magic + version
        entry_count = self.u32be()
        toc_size = entry_count * 16
        toc_names_length = self.u32be()
        self.encryption = self.rpf.ENCRYPTION_TYPE.get(self.u32be(), 0x0FEFFFF8) # Fallback is AES

        # Decrypt the TOC
        if(self.encryption == 'None' or self.encryption == 'Open'):
            Logger.log("No Encryption...")
            entries_data = self.read( toc_size )
            names_data = self.read(toc_names_length)
        
        elif(self.encryption == 'AES'):
            Logger.log("AES Encryption...")
            decryptor = AES.new(self.rpf.KEYS_PS3[self.version].to_bytes(32, self.endianness), AES.MODE_ECB) #  Hardcoded for ps3 right now
            decryptor.block_size = 128

            entries_data_enc = self.read( toc_size )
            entries_data = decryptor.decrypt(entries_data_enc)

            names_data_enc = self.read(toc_names_length)
            names_data = decryptor.decrypt(names_data_enc)
            
        elif(self.encryption == 'NG'):
            Logger.log("NG Encryption... Not Implemented")   # I think only the PC uses this

        # Parse the TOC
        Logger.log("Reading TOC Entries...")
        toc = self.parse_toc(bytearray(entries_data))
        for entry in toc:
            entry:RPF7TOCEntry
            # Name and print entries
            if(entry.filetype == entry.FILETYPES['Binary']):
                entry.name = bytes_to_string(names_data, entry.name_offset)
                entry.print_entry()

            if(entry.filetype == entry.FILETYPES['Directory']):
                Logger.log("Directory --")
            
            # Add size of the entries to the length
            if(entry.size == 0):
                self.size += entry.uncompressed_size
            else:
                self.size += entry.size
        
        # Add header size to the length
        self.size += 16 + toc_size #+ toc_names_length

        # Align to 0x800
        self.size = ((self.size + 0x800) & ~(0x800 - 1))

        Logger.log("Filesize: "+str(self.size))

    def parse_toc(self, toc_decrypted):
        toc = []
        for i in range(0, len(toc_decrypted), 16):
            
            entry = RPF7TOCEntry()
            toc.append(entry)

            # Ident
            x = toc_decrypted[i:i+4]

            # Directory
            if(x == b'\x7F\xFF\xFF\x00'):
                Logger.log("Detected: Directory")
                entry.filetype = entry.FILETYPES['Directory']
            
            # Binary
            elif( (int.from_bytes(x,self.endianness,signed=False) & 0x80000000) == 0 ):
                Logger.log("Detected: Binary")
                entry.filetype = entry.FILETYPES['Binary']

                x = toc_decrypted[i:i+8]
                entry.name_offset = int.from_bytes(x,self.endianness,signed = False) & 0xFFFF
                entry.size = (int.from_bytes(x,self.endianness,signed = False) >> 16 ) & 0xFFFFFF
                entry.file_offset = ((int.from_bytes(x,self.endianness,signed = False) >> 40 ) & 0xFFFFFF) * 512

                x = toc_decrypted[i+8:i+12] #uncompressed size
                entry.uncompressed_size = int.from_bytes(x,self.endianness,signed = False)

                # Last 4 bytes have to do with encryption - we shouldn't need them

            # Resource File
            else:
                Logger.log("Detected: Resource")
                entry.filetype = entry.FILETYPES['Resource']

                # Size
                x = toc_decrypted[i+2:i+5]
                Logger.log(f"Size: {x.hex()}")

                if ( x == b'\xFF\xFF\xFF' ): # If the size is too big for 3 bytes you need to get it from the resource file

                    # Resource file offset
                    x = toc_decrypted[i+5:i+8]
                    Logger.log(x)

                    # Calculate the offset
                    resourcefile_offset = ( int.from_bytes(x,self.endianness,signed = False) & 0x7FFFFF) * 512
                    
                    startingOffset = self.offset
                    self.seek(resourcefile_offset)
                    buf = self.read(16)

                    self.seek(startingOffset)

                    # Get size from resource file flags
                    x = bytearray()
                    x.append(buf[7])
                    x.append(buf[14])
                    x.append(buf[5])
                    x.append(buf[2])
                    
                entry.size = int.from_bytes(x,self.endianness)

        return toc


#
# END RPF FILES
#

all_filecarvers = [a_filecarver for a_filecarver in FileCarver.__subclasses__()]
#all_filecarvers = [UnrealTOCCarver]


class FileCarverScanner():
    def __init__(self, stream):
        #self._superblock = SuperBlock(self._stream)
        self.identified_file_sigs = []
    
    def scan(self, stream, loadpath, start=0, end=0, interval=None):
        Logger.log("Beginning FileCarver scan...")

        if os.path.exists(loadpath + '\\filecarver.txt'):
            self._load_from_files(stream, loadpath)
            return

        if end == 0:
            stream.seek(0, 2)
            end = stream.tell()
            stream.seek(0, 0)
        
        if interval == None:
            #interval = self._superblock.fsize
            interval = 0x800

        global all_filecarvers
        for offset in range(start, end, interval):
            for carver in all_filecarvers:
                tester = carver(stream, offset)
                stream.seek(offset)
                if tester.test():
                    stream.seek(offset)
                    Logger.log(f"Found {tester.__class__.__name__}... at offset 0x{offset:X}")
                    self.identified_file_sigs.append(tester)
            if (offset & 0xfffffff) == 0:
                percent = round((offset/end)*100,2)
                Logger.log(f"Percent Complete: {percent}%")
        
        self._save_scan_to_files(loadpath)
        self.parse_identified_file_sigs()

    def parse_identified_file_sigs(self):
        Logger.log("Parsing found files...")
        global all_filecarvers
        for carver in self.identified_file_sigs:
            Logger.log(f"Parsing {carver.__class__.__name__}...")
            carver:FileCarver
            carver.seek(0)
            carver.parse()

    def get_nodes(self):
        nodes = []
        for file_carver in self.identified_file_sigs:
            node = Node(NodeType.FILE)
            if file_carver.name != '':
                node.set_name(file_carver.name)
            if file_carver.extension != '':
                node.set_file_ext(file_carver.extension)
            node.set_file_offset(file_carver.offset)
            node.set_size(file_carver.size)
            nodes.append(node)
        return nodes

    def _save_scan_to_files(self, loadpath):
        if not os.path.exists(loadpath + "\\"):
            os.mkdir(loadpath + "\\")
        with open(loadpath + '\\filecarver.txt', 'a') as fp:
            for fc in self.identified_file_sigs:
                fp.write(f"{fc.offset}\n")
        Logger.log(f"Saved file scanner files to: {loadpath}")

    def _load_from_files(self, stream, loadpath):
        Logger.log(f"Loading file scanner results from files at: {loadpath}")
        filecarver_list = []
        with open(loadpath + '\\filecarver.txt', 'r') as fp:
            filecarver_list = fp.readlines()

        for line in filecarver_list:
            offset = int(line.strip())
            for carver in all_filecarvers:
                tester = carver(stream, offset)
                stream.seek(offset)
                if tester.test():
                    stream.seek(offset)
                    Logger.log(f"Found {tester.__class__.__name__}... at offset 0x{offset:X}")
                    self.identified_file_sigs.append(tester)

        self.parse_identified_file_sigs()


class InodeIdentifier():
    def __init__(self, stream):
        self._stream = stream
        self._superblock = SuperBlock(self._stream)
        self._max_block_index = self._stream.getLength() / self._superblock.fsize

    def identify_unk_inode_filetype(self, inode):
        for file_sig in all_filecarvers:
            # if inode.db[0] > self._max_block_index:      # This shouldn't happen. No inodes should get past the scan that have invalid db bindex
            #     continue
            offset = inode.db[0] * self._superblock.fsize
            self._stream.seek(offset)
            tester = file_sig(self._stream, offset)
            if tester.test():
                return tester
        return None