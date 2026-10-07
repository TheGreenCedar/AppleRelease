"""Final-app tar contract. No candidate code is executed while archiving or comparing."""
import os
import posixpath
import stat
import tarfile
from pathlib import Path, PurePosixPath

from policy import MAX_MEMBER, MAX_UNPACKED, digest_file, require
from safe_zip import safe_name


def inventory(bundle):
    bundle = Path(bundle)
    require(bundle.is_dir() and not bundle.is_symlink(), 'Updater app root must be a directory.')
    result = {}
    def visit(path):
        name = str(path.relative_to(bundle.parent).as_posix())
        safe_name(name)
        details = path.lstat(); mode = details.st_mode
        require(not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX), 'Special updater file mode.')
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            require(target and not target.startswith('/') and '\\' not in target
                    and not any(ord(c) < 32 for c in target), 'Unsafe updater symbolic link.')
            require(path.resolve().is_relative_to(bundle.resolve()), 'Updater symbolic link escapes app.')
            result[name] = ('link', stat.S_IMODE(mode), target)
        elif stat.S_ISDIR(mode):
            result[name] = ('directory', stat.S_IMODE(mode))
            for child in sorted(path.iterdir()): visit(child)
        else:
            require(stat.S_ISREG(mode) and details.st_size <= MAX_MEMBER, 'Special or oversized updater member.')
            result[name] = ('file', stat.S_IMODE(mode), details.st_size, digest_file(path))
    visit(bundle)
    require(len(result) <= 2048, 'Too many updater members.')
    require(sum(item[2] for item in result.values() if item[0] == 'file') <= MAX_UNPACKED, 'Updater app too large.')
    return result


def create(bundle, archive):
    """One canonical app root; preserve the signed bytes, modes and relative links."""
    bundle = Path(bundle); archive = Path(archive)
    before = inventory(bundle)
    require(not archive.exists(), 'Updater archive already exists.')
    with archive.open('xb') as output, tarfile.open(fileobj=output, mode='w:gz', format=tarfile.PAX_FORMAT) as writer:
        for name in before:
            path = bundle.parent / name
            writer.inodes.clear()  # Encode inode-shared files as bytes, never as tar hard links.
            member = writer.gettarinfo(str(path), arcname=name)
            # Do not encode build-runner identity; signed app file bytes remain unchanged.
            member.uid = member.gid = 0; member.uname = member.gname = ''
            if member.isreg():
                with path.open('rb') as source: writer.addfile(member, source)
            else: writer.addfile(member)
    require(inventory(bundle) == before, 'Final app changed during updater archiving.')
    return before


def extract(archive, destination, root_name):
    """Manual bounded extraction, deferring links so members cannot traverse them."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    seen = set(); links = []; directories = []; total = 0
    with tarfile.open(archive, 'r:gz') as reader:
        for member in reader:
            parts = safe_name(member.name)
            require(parts[0] == root_name, 'Unexpected updater app root.')
            require(member.name not in seen and len(seen) < 2048, 'Duplicate or excess updater member.')
            seen.add(member.name)
            require(member.isdir() or member.isreg() or member.issym(), 'Special updater archive member.')
            require(not member.mode & ~0o777, 'Special updater archive permissions.')
            require(0 <= member.size <= MAX_MEMBER, 'Updater archive member too large.')
            total += member.size; require(total <= MAX_UNPACKED, 'Updater archive too large.')
            path = destination.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True); directories.append((path, member.mode)); continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                target = member.linkname
                require(target and not target.startswith('/') and '\\' not in target
                        and not any(ord(c) < 32 for c in target), 'Unsafe updater symbolic link.')
                resolved = posixpath.normpath(posixpath.join(str(PurePosixPath(member.name).parent), target))
                require(resolved == root_name or resolved.startswith(root_name + '/'), 'Updater link escapes app.')
                links.append((path, target)); continue
            source = reader.extractfile(member); require(source is not None, 'Missing updater file bytes.')
            copied = 0
            with source, path.open('xb') as output:
                while block := source.read(1024 ** 2):
                    copied += len(block); require(copied <= member.size, 'Updater member overflow.'); output.write(block)
            require(copied == member.size, 'Truncated updater member.')
            path.chmod(member.mode)
    require(root_name in seen and any(name.startswith(root_name + '/Contents/') for name in seen), 'Updater app contents missing.')
    for path, target in links: os.symlink(target, path)
    for path, mode in sorted(directories, key=lambda item: len(item[0].parts), reverse=True): path.chmod(mode)
    bundle = destination / root_name
    inventory(bundle)  # Recheck link chains, actual modes and the resulting bounded tree.
    return bundle


def verify(archive, destination, bundle):
    original = inventory(bundle)
    extracted = extract(archive, destination, Path(bundle).name)
    require(inventory(extracted) == original, 'Updater archive differs from the final signed app.')
    return extracted
