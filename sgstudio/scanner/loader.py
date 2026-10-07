"""Turn a user-supplied path (folder or .zip) into a folder we can read (port of loader.js).

Zips are unpacked defensively: names are never trusted (no ../ traversal, absolute paths,
symlinks, oversized files or zip bombs) and Mac junk is skipped. Nothing from the site is executed.
"""
import os
import shutil
import tempfile
import zipfile

from .util import LIMITS, SKIP_DIRS, ScanError, rx

_MAC_DIR = rx(r'^__MACOSX\/')
_DS_STORE = rx(r'(^|\/)\.DS_Store$')
_APPLE_DOUBLE = rx(r'(^|\/)\._[^/]*$')
_DRIVE = rx(r'^[A-Za-z]:')
_INDEX_FILE = rx(r'^index\.(html?|php)$', 'i')
_ZIP_EXT = rx(r'\.zip$', 'i')


def _entry_name(info):
    """The entry name as raw bytes decoded as UTF-8 (this is what the Node version did)."""
    raw = info.orig_filename.encode('utf-8' if info.flag_bits & 0x800 else 'cp437', 'surrogateescape')
    return raw.decode('utf-8', 'replace')


def extract_zip(zip_path, dest_dir, warnings):
    """Safely unpack a zip into dest_dir. Returns the number of files written."""
    try:
        zf = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError, EOFError, ValueError, NotImplementedError) as e:
        msg = 'ADM-ZIP: Invalid or unsupported zip format. No END header found' if isinstance(e, zipfile.BadZipFile) else str(e)
        raise ScanError('ZIP file kharab hai ya khul nahi raha: ' + msg)
    with zf:
        entries = zf.infolist()
        if len(entries) > LIMITS['maxZipEntries']:
            raise ScanError('ZIP mein bahut zyada files hain (%d)' % len(entries))
        total = 0
        extracted = 0
        dest_prefix = dest_dir + os.sep
        for info in entries:
            raw_name = _entry_name(info)
            if raw_name.endswith('/') or raw_name.endswith('\\'):
                continue  # directory
            name = raw_name.replace('\\', '/')
            if _MAC_DIR.search(name) or _DS_STORE.search(name) or _APPLE_DOUBLE.search(name):
                continue
            if name.startswith('/') or _DRIVE.search(name) or '..' in name.split('/'):
                warnings.append({'code': 'zip-unsafe-path', 'file': name})
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                warnings.append({'code': 'zip-symlink-skipped', 'file': name})
                continue
            declared = info.file_size or 0
            if declared > LIMITS['maxZipFileBytes']:
                warnings.append({'code': 'zip-file-too-large', 'file': name})
                continue
            total += declared
            if total > LIMITS['maxZipTotalBytes']:
                raise ScanError('ZIP kholne par bahut bada ho jata hai (zip bomb jaisa), roka gaya')
            if '\x00' in name:
                warnings.append({'code': 'zip-unsafe-path', 'file': name})
                continue
            target = os.path.normpath(os.path.join(dest_dir, name))
            if not target.startswith(dest_prefix):
                warnings.append({'code': 'zip-unsafe-path', 'file': name})
                continue
            try:
                # read at most limit+1 bytes: the declared size in a zip header can lie
                with zf.open(info) as fh:
                    data = fh.read(LIMITS['maxZipFileBytes'] + 1)
            except Exception:
                warnings.append({'code': 'zip-entry-unreadable', 'file': name})
                continue
            if len(data) > LIMITS['maxZipFileBytes']:
                warnings.append({'code': 'zip-file-too-large', 'file': name})
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, 'wb') as out:
                out.write(data)
            extracted += 1
    return extracted


def _sorted_entries(d):
    with os.scandir(d) as it:
        return sorted(it, key=lambda e: os.fsencode(e.name))


def find_site_root(d):
    """Shallowest folder that holds an index page (zips often wrap the site in an extra folder)."""
    queue = [(d, 0)]
    while queue:
        cur, depth = queue.pop(0)
        try:
            ents = _sorted_entries(cur)
        except OSError:
            continue
        for e in ents:
            if e.is_file(follow_symlinks=False) and _INDEX_FILE.search(e.name):
                return cur
        if depth < 3:
            for e in ents:
                if e.is_dir(follow_symlinks=False) and e.name not in SKIP_DIRS and not e.name.startswith('.'):
                    queue.append((os.path.join(cur, e.name), depth + 1))
    return d


class Loaded(dict):
    """Result of prepare_input: a dict with attribute access (root, name, source, rootRel, warnings)."""

    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)

    def cleanup(self):
        fn = self.get('_cleanup')
        if fn:
            fn()
            self['_cleanup'] = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False


def _rel(root, base):
    r = os.path.relpath(root, base)
    return '' if r == '.' else r.replace(os.sep, '/')


def prepare_input(input_path):
    """Turn a folder or .zip path into a readable folder.

    Returns a Loaded dict {root, name, source, rootRel, warnings} with a cleanup() method.
    """
    input_path = os.fspath(input_path)
    warnings = []
    absp = os.path.abspath(input_path)
    try:
        st = os.stat(absp)
    except OSError:
        raise ScanError('Path nahi mila: ' + input_path)
    import stat as _stat
    if _stat.S_ISDIR(st.st_mode):
        real = os.path.realpath(absp)
        root = find_site_root(real)
        return Loaded(root=root, name=os.path.basename(real), source='folder', rootRel=_rel(root, real), warnings=warnings, _cleanup=None)
    if _stat.S_ISREG(st.st_mode) and _ZIP_EXT.search(absp):
        tmp = os.path.realpath(tempfile.mkdtemp(prefix='sg-scan-'))
        try:
            n = extract_zip(absp, tmp, warnings)
            if n == 0:
                raise ScanError('ZIP khaali hai ya usme koi file nahi mili')
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        root = find_site_root(tmp)
        return Loaded(
            root=root,
            name=_ZIP_EXT.sub('', os.path.basename(absp)),
            source='zip',
            rootRel=_rel(root, tmp),
            warnings=warnings,
            _cleanup=lambda: shutil.rmtree(tmp, ignore_errors=True),
        )
    raise ScanError('Sirf folder ya .zip file chalegi: ' + input_path)
