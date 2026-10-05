"""Bounded archive extraction with no path traversal, external links or special files."""
import os
import posixpath
import stat
import zipfile
from pathlib import Path, PurePosixPath
from policy import MAX_MEMBER, MAX_UNPACKED, ReleaseError, require

def safe_name(name):
    require(name and '\\' not in name and not any(ord(char)<32 for char in name),'Invalid archive name.')
    parts=PurePosixPath(name).parts
    require(not name.startswith('/') and all(p not in {'..','.'} for p in parts),'Archive path traversal.')
    require(posixpath.normpath(name.rstrip('/'))==name.rstrip('/'),'Noncanonical archive path.')
    return parts

def extract(archive, destination, *, root_name=None, expected_files=None):
    destination=Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    require(not any(destination.iterdir()),'Extraction destination must be empty.')
    links=[];seen=set();total=0
    with zipfile.ZipFile(archive) as reader:
        require(len(reader.infolist())<=2048,'Too many archive entries.')
        for member in reader.infolist():
            parts=safe_name(member.filename)
            require(member.filename not in seen,'Duplicate archive entry.');seen.add(member.filename)
            if root_name:require(parts[0]==root_name,'Unexpected application archive root.')
            if expected_files:require(member.filename in expected_files,'Unexpected artifact member.')
            require(not member.flag_bits&1,'Encrypted archive members are not accepted.')
            total+=member.file_size
            require(0<=member.file_size<=MAX_MEMBER and total<=MAX_UNPACKED,'Archive exceeds extraction limits.')
            path=destination.joinpath(*parts)
            mode=member.external_attr>>16;kind=stat.S_IFMT(mode)
            require(kind in {0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK},'Special archive file rejected.')
            if member.is_dir():path.mkdir(parents=True,exist_ok=True);continue
            path.parent.mkdir(parents=True,exist_ok=True)
            if kind==stat.S_IFLNK:
                require(root_name is not None and member.file_size<=4096,'Unexpected symbolic link.')
                target=reader.read(member).decode('utf-8')
                require(target and not target.startswith('/') and '\\' not in target and not any(ord(c)<32 for c in target),'Unsafe symbolic link.')
                resolved=posixpath.normpath(posixpath.join(str(PurePosixPath(member.filename).parent),target))
                require(resolved==root_name or resolved.startswith(root_name+'/'),'Symbolic link escapes application.')
                links.append((path,target));continue
            copied=0
            with reader.open(member) as source,path.open('xb') as output:
                while block:=source.read(1024**2):
                    copied+=len(block);require(copied<=member.file_size,'Archive member overflow.');output.write(block)
            require(copied==member.file_size,'Truncated archive member.')
            path.chmod((mode&0o777) or 0o644)
    if expected_files:require(seen==set(expected_files),'Missing artifact member.')
    # Create links after regular files, so extraction never traverses a producer link.
    for path,target in links:os.symlink(target,path)
    if root_name:
        root=(destination/root_name).resolve()
        for path,_ in links:
            require(path.resolve().is_relative_to(root),'Symbolic link chain escapes application.')
    return destination/root_name if root_name else destination
