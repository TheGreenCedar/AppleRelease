"""Preserve PyInstaller 6.22.3 payloads while transforming embedded Mach-O signatures.

No marshaled script/PYZ entry is loaded or executed. Private upstream format helpers
are deliberately version-pinned and covered by payload-preservation tests.
"""
import hashlib
import importlib.metadata
import struct
import zlib
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from PyInstaller.archive.writers import CArchiveWriter
from policy import MAX_MEMBER, MAX_UNPACKED, require
from safe_zip import safe_name

MACHO={b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xce',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'}

def is_macho(data):return data[:4] in MACHO

def unpack_entry(reader,name):
    offset,compressed_length,length,compressed,kind=reader.toc[name]
    require(0<=length<=MAX_MEMBER and 0<=compressed_length<=MAX_MEMBER,'Embedded entry exceeds size limit.')
    with open(reader._filename,'rb') as source:
        source.seek(reader._start_offset+offset);raw=source.read(compressed_length)
    require(len(raw)==compressed_length,'Truncated embedded entry.')
    if not compressed:
        require(len(raw)==length,'Embedded entry size mismatch.');return raw
    decoder=zlib.decompressobj();data=decoder.decompress(raw,length+1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and len(data)==length,'Embedded decompression limit or integrity failure.')
    return data

def rebuild(source,destination,transform):
    require(importlib.metadata.version('pyinstaller')=='6.22.3','Unsupported PyInstaller archive adapter version.')
    source=Path(source);destination=Path(destination);reader=CArchiveReader(str(source))
    require(0<reader._start_offset<reader._end_offset<=source.stat().st_size,'Invalid embedded archive bounds.')
    require(len(reader.toc)<=1024 and sum(entry[2] for entry in reader.toc.values())<=MAX_UNPACKED,'Embedded archive exceeds bounds.')
    with source.open('rb') as stream:
        stream.seek(reader._end_offset-reader._COOKIE_LENGTH);cookie=struct.unpack(reader._COOKIE_FORMAT,stream.read(reader._COOKIE_LENGTH))
    fingerprints={};changed=[];toc=[]
    with source.open('rb') as original,destination.open('xb') as output:
        remaining=reader._start_offset
        while remaining:
            block=original.read(min(1024**2,remaining));require(block,'Truncated executable prefix.');output.write(block);remaining-=len(block)
        writer=CArchiveWriter.__new__(CArchiveWriter)
        for name,entry in reader.toc.items():
            safe_name(name);require(entry[4] in {'b','x','z','m','M','s','S','n','d'},'Unsupported embedded entry type.')
            data=unpack_entry(reader,name);fingerprints[name]=hashlib.sha256(data).hexdigest()
            offset=output.tell()-reader._start_offset
            if is_macho(data):
                require(entry[4]=='b','Native code must be classified as a binary.')
                transformed=transform(name,data);require(is_macho(transformed),'Native transformation lost Mach-O header.')
                item=writer._write_blob(output,transformed,name,entry[4],bool(entry[3]));toc.append((offset,*item[1:]));changed.append(name)
            else:
                original.seek(reader._start_offset+entry[0]);raw=original.read(entry[1]);require(len(raw)==entry[1],'Truncated archive payload.');output.write(raw)
                toc.append((offset,entry[1],entry[2],entry[3],entry[4],name))
        for option in reader.options:toc.append((output.tell()-reader._start_offset,0,0,0,'o',option))
        toc_offset=output.tell()-reader._start_offset;table=writer._serialize_toc(toc);output.write(table)
        length=output.tell()-reader._start_offset+writer._COOKIE_LENGTH
        output.write(struct.pack(writer._COOKIE_FORMAT,writer._COOKIE_MAGIC_PATTERN,length,toc_offset,len(table),cookie[4],cookie[5]))
    destination.chmod(source.stat().st_mode&0o777)
    after=CArchiveReader(str(destination))
    require(set(after.toc)==set(reader.toc) and after.options==reader.options,'Embedded archive inventory changed.')
    for name in reader.toc:
        if name not in changed:require(hashlib.sha256(unpack_entry(after,name)).hexdigest()==fingerprints[name],'Non-native embedded payload changed.')
    return changed
