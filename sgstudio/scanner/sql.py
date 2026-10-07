"""Read table structure out of a MySQL dump WITHOUT keeping any row data. Port of sql.js."""
import codecs
import gzip
import re
import zlib

from .util import rx, to16

_ENQUIRY_COLS = rx(r'^(name|full_?name|first_?name|email|e_?mail|phone|mobile|contact|contact_?no|whatsapp|message|msg|comments?|enquiry|inquiry|query|requirement|subject|city|service)$', 'i')
_ENQUIRY_TABLE = rx(r'enquir|inquir|contact|lead|quer(y|ies)|message|submission|request|feedback|booking|appointment|callback|form', 'i')
_END_TABLE = rx(r'^\)[^;]*;?\s*$')
_COLUMN = rx(r'^\s*[`"]([^`"]+)[`"]\s+(\w+(?:\([^)]*\))?)')
_PRIMARY = rx(r'^\s*PRIMARY\s+KEY', 'i')
_CREATE = rx(r'^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?([\w$]+)[`"]?\s*\(', 'i')
_ONE_LINE_END = rx(r'\)\s*(ENGINE|;)', 'i')
_INSERT = rx(r'^\s*INSERT\s+(?:IGNORE\s+)?INTO\s+[`"]?([\w$]+)[`"]?', 'i')
_MAIL = rx(r'mail', 'i')
_MAIL_PHONE = rx(r'mail|phone|mobile', 'i')
_STATUS = rx(r'^(status|is_read|read|state)$', 'i')
_DATE = rx(r'(created|date|time|added|submitted)', 'i')
_LINE_SPLIT = re.compile(r'\r\n|\n|\r')


def _gz_message(e):
    """Map Python's gzip/zlib error texts onto the ones Node's zlib reports (kept for report parity)."""
    msg = str(e)
    if isinstance(e, EOFError):
        return 'unexpected end of file'
    if isinstance(e, gzip.BadGzipFile):
        if 'CRC check failed' in msg:
            return 'incorrect data check'
        if 'Incorrect length' in msg:
            return 'incorrect length check'
        return 'incorrect header check'
    return msg.split(': ', 1)[1] if ': ' in msg else msg


def _read_lines(abs_path):
    """Yield text lines of a .sql / .sql.gz file, streaming (like Node's readline)."""
    opener = gzip.open if re.search(r'\.gz$', abs_path, re.I) else open
    dec = codecs.getincrementaldecoder('utf-8')('replace')
    buf = ''
    try:
        with opener(abs_path, 'rb') as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                buf += dec.decode(chunk)
                # a '\r' at the very end may be the first half of '\r\n': wait for the next chunk
                hold = '\r' if buf.endswith('\r') else ''
                parts = _LINE_SPLIT.split(buf[:-1] if hold else buf)
                buf = parts.pop() + hold
                for line in parts:
                    yield to16(line)
            buf += dec.decode(b'', final=True)
    except (EOFError, gzip.BadGzipFile, zlib.error) as e:
        raise OSError(_gz_message(e))
    parts = _LINE_SPLIT.split(buf)
    last = parts.pop()
    for line in parts:
        yield to16(line)
    if last != '':
        yield to16(last)


def parse_dump(abs_path):
    """Read table structure out of a MySQL dump without keeping any row data.

    Streams line by line, so a 500 MB dump costs almost no memory. Handles .sql and .sql.gz.
    Returns {'tables': [...], 'lines': n}.
    """
    tables = {}
    cur = None
    lines = 0
    for line in _read_lines(abs_path):
        lines += 1
        if cur is not None:
            if _END_TABLE.search(line):
                cur = None
                continue
            col = _COLUMN.search(line)
            if col:
                cur['columns'].append({'name': col.group(1), 'type': col.group(2).lower()})
            elif _PRIMARY.search(line):
                cur['hasPrimaryKey'] = True
            continue
        ct = _CREATE.search(line)
        if ct:
            cur = {'name': ct.group(1), 'columns': [], 'inserts': 0, 'hasPrimaryKey': False}
            tables[ct.group(1)] = cur
            # one-line CREATE TABLE (...); rare, give up on columns but keep the table
            if _ONE_LINE_END.search(line):
                cur = None
            continue
        ins = _INSERT.search(line)
        if ins and ins.group(1) in tables:
            tables[ins.group(1)]['inserts'] += 1
    out = []
    for t in tables.values():
        names = [c['name'] for c in t['columns']]
        col_hits = len([n for n in names if _ENQUIRY_COLS.search(n)])
        score = col_hits + (2 if _ENQUIRY_TABLE.search(t['name']) else 0) + (1 if any(_MAIL.search(n) for n in names) else 0)
        out.append({
            'name': t['name'],
            'columns': t['columns'],
            'insertStatements': t['inserts'],
            'enquiryScore': score,
            'looksLikeEnquiries': score >= 4 and any(_MAIL_PHONE.search(n) for n in names),
            'hasStatusColumn': any(_STATUS.search(n) for n in names),
            'hasDateColumn': any(_DATE.search(n) for n in names),
        })
    return {'tables': out, 'lines': lines}
