"""A pure-Python HTML5 parser that mirrors parse5 (the parser behind cheerio in the Node scanner).

Only the pieces the scanner needs are exposed: a tree of Elements/Text/Comment nodes where every
element knows the line it starts on and the line it ends on, plus a few query helpers.
It follows the WHATWG tree-construction rules (implied tags, table foster parenting, the form
element pointer, adoption agency ...), because real-world micro-sites are full of broken markup and
the scanner's answers (which fields belong to which form ...) depend on how a browser would read it.

Nothing here ever executes anything: it is only text -> tree.
"""
import bisect
import html.entities
import re

from .util import to16

# --------------------------------------------------------------------------- tree

NS_HTML = 'html'
NS_SVG = 'svg'
NS_MATHML = 'math'


class Node(object):
    __slots__ = ('parent',)


class Text(Node):
    __slots__ = ('data',)

    def __init__(self, data):
        self.parent = None
        self.data = data


class Comment(Node):
    __slots__ = ('data',)

    def __init__(self, data):
        self.parent = None
        self.data = data


class Fragment(Node):
    """Document root and <template> contents."""
    __slots__ = ('children', 'doc_mode', 'doctype')

    def __init__(self):
        self.parent = None
        self.children = []
        self.doc_mode = 'no-quirks'
        self.doctype = None


class Element(Node):
    __slots__ = ('name', 'tid', 'ns', 'attrs', 'children', 'has_loc', 'start_line', 'end_line', 'end_tag')

    def __init__(self, name, ns, attrs):
        self.parent = None
        self.name = name
        self.tid = name
        self.ns = ns
        self.attrs = {}
        for a in attrs:
            self.attrs[a[0]] = a[1]
        self.children = []
        self.has_loc = False
        self.start_line = None
        self.end_line = None
        self.end_tag = False


def _append(parent, node):
    parent.children.append(node)
    node.parent = parent


def _detach(node):
    p = node.parent
    if p is not None:
        for i, c in enumerate(p.children):
            if c is node:
                del p.children[i]
                break
        node.parent = None


def _insert_before(parent, node, ref):
    for i, c in enumerate(parent.children):
        if c is ref:
            parent.children.insert(i, node)
            break
    else:
        parent.children.append(node)
    node.parent = parent


def _index_of(parent, node):
    for i, c in enumerate(parent.children):
        if c is node:
            return i
    return -1


# --------------------------------------------------------------------------- tag tables

SPECIAL_HTML = frozenset(
    'address applet area article aside base basefont bgsound blockquote body br button caption center col colgroup dd '
    'details dir div dl dt embed fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header '
    'hgroup hr html iframe img input li link listing main marquee menu meta nav noembed noframes noscript object ol p '
    'param plaintext pre script section select source style summary table tbody td template textarea tfoot th thead '
    'title tr track ul wbr xmp'.split()
)
SPECIAL_MATHML = frozenset(['mi', 'mo', 'mn', 'ms', 'mtext', 'annotation-xml'])
SPECIAL_SVG = frozenset(['title', 'foreignObject', 'desc'])
NUMBERED_HEADERS = frozenset(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])

IMPLICIT_END = frozenset(['dd', 'dt', 'li', 'optgroup', 'option', 'p', 'rb', 'rp', 'rt', 'rtc'])
IMPLICIT_END_THOROUGH = IMPLICIT_END | frozenset(['caption', 'colgroup', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr'])
SCOPING_HTML = frozenset(['applet', 'caption', 'html', 'marquee', 'object', 'table', 'td', 'template', 'th'])
SCOPING_HTML_LIST = SCOPING_HTML | frozenset(['ol', 'ul'])
SCOPING_HTML_BUTTON = SCOPING_HTML | frozenset(['button'])
SCOPING_MATHML = frozenset(['annotation-xml', 'mi', 'mn', 'mo', 'ms', 'mtext'])
SCOPING_SVG = frozenset(['desc', 'foreignObject', 'title'])
TABLE_ROW_CONTEXT = frozenset(['tr', 'template', 'html'])
TABLE_BODY_CONTEXT = frozenset(['tbody', 'tfoot', 'thead', 'template', 'html'])
TABLE_CONTEXT = frozenset(['table', 'template', 'html'])
TABLE_CELLS = frozenset(['td', 'th'])
TABLE_STRUCTURE = frozenset(['table', 'tbody', 'tfoot', 'thead', 'tr'])
TABLE_VOID = frozenset(['caption', 'col', 'colgroup', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr'])
FORMATTING_B = frozenset(['i', 's', 'b', 'u', 'em', 'tt', 'big', 'code', 'font', 'small', 'strike', 'strong'])
ADDRESS_LIKE = frozenset(
    'p dl ol ul div dir nav main menu aside center figure footer header hgroup dialog details address article search '
    'section summary fieldset blockquote figcaption'.split()
)
ADDRESS_END = frozenset(
    'dl ul ol dir div nav pre main menu aside button center figure footer header hgroup dialog address article details '
    'search section summary listing fieldset blockquote figcaption'.split()
)
EXITS_FOREIGN = frozenset(
    'b big blockquote body br center code dd div dl dt em embed h1 h2 h3 h4 h5 h6 head hr i img li listing menu meta '
    'nobr ol p pre ruby s small span strong strike sub sup table tt u ul var'.split()
)

SVG_ATTRS = dict(
    (a.lower(), a)
    for a in (
        'attributeName attributeType baseFrequency baseProfile calcMode clipPathUnits diffuseConstant edgeMode filterUnits '
        'glyphRef gradientTransform gradientUnits kernelMatrix kernelUnitLength keyPoints keySplines keyTimes lengthAdjust '
        'limitingConeAngle markerHeight markerUnits markerWidth maskContentUnits maskUnits numOctaves pathLength '
        'patternContentUnits patternTransform patternUnits pointsAtX pointsAtY pointsAtZ preserveAlpha preserveAspectRatio '
        'primitiveUnits refX refY repeatCount repeatDur requiredExtensions requiredFeatures specularConstant '
        'specularExponent spreadMethod startOffset stdDeviation stitchTiles surfaceScale systemLanguage tableValues targetX '
        'targetY textLength viewBox viewTarget xChannelSelector yChannelSelector zoomAndPan'
    ).split()
)
SVG_TAGS = dict(
    (t.lower(), t)
    for t in (
        'altGlyph altGlyphDef altGlyphItem animateColor animateMotion animateTransform clipPath feBlend feColorMatrix '
        'feComponentTransfer feComposite feConvolveMatrix feDiffuseLighting feDisplacementMap feDistantLight feFlood '
        'feFuncA feFuncB feFuncG feFuncR feGaussianBlur feImage feMerge feMergeNode feMorphology feOffset fePointLight '
        'feSpecularLighting feSpotLight feTile feTurbulence foreignObject glyphRef linearGradient radialGradient textPath'
    ).split()
)
XML_ATTRS = frozenset(
    ['xlink:actuate', 'xlink:arcrole', 'xlink:href', 'xlink:role', 'xlink:show', 'xlink:title', 'xlink:type', 'xml:lang', 'xml:space', 'xmlns', 'xmlns:xlink']
)

QUIRKS_PUBLIC_PREFIXES = (
    '+//silmaril//dtd html pro v0r11 19970101//', '-//as//dtd html 3.0 aswedit + extensions//',
    '-//advasoft ltd//dtd html 3.0 aswedit + extensions//', '-//ietf//dtd html 2.0 level 1//',
    '-//ietf//dtd html 2.0 level 2//', '-//ietf//dtd html 2.0 strict level 1//', '-//ietf//dtd html 2.0 strict level 2//',
    '-//ietf//dtd html 2.0 strict//', '-//ietf//dtd html 2.0//', '-//ietf//dtd html 2.1e//', '-//ietf//dtd html 3.0//',
    '-//ietf//dtd html 3.2 final//', '-//ietf//dtd html 3.2//', '-//ietf//dtd html 3//', '-//ietf//dtd html level 0//',
    '-//ietf//dtd html level 1//', '-//ietf//dtd html level 2//', '-//ietf//dtd html level 3//',
    '-//ietf//dtd html strict level 0//', '-//ietf//dtd html strict level 1//', '-//ietf//dtd html strict level 2//',
    '-//ietf//dtd html strict level 3//', '-//ietf//dtd html strict//', '-//ietf//dtd html//',
    '-//metrius//dtd metrius presentational//', '-//microsoft//dtd internet explorer 2.0 html strict//',
    '-//microsoft//dtd internet explorer 2.0 html//', '-//microsoft//dtd internet explorer 2.0 tables//',
    '-//microsoft//dtd internet explorer 3.0 html strict//', '-//microsoft//dtd internet explorer 3.0 html//',
    '-//microsoft//dtd internet explorer 3.0 tables//', '-//netscape comm. corp.//dtd html//',
    '-//netscape comm. corp.//dtd strict html//', "-//o'reilly and associates//dtd html 2.0//",
    "-//o'reilly and associates//dtd html extended 1.0//", "-//o'reilly and associates//dtd html extended relaxed 1.0//",
    '-//sq//dtd html 2.0 hotmetal + extensions//',
    '-//softquad software//dtd hotmetal pro 6.0::19990601::extensions to html 4.0//',
    '-//softquad//dtd hotmetal pro 4.0::19971010::extensions to html 4.0//', '-//spyglass//dtd html 2.0 extended//',
    '-//sun microsystems corp.//dtd hotjava html//', '-//sun microsystems corp.//dtd hotjava strict html//',
    '-//w3c//dtd html 3 1995-03-24//', '-//w3c//dtd html 3.2 draft//', '-//w3c//dtd html 3.2 final//',
    '-//w3c//dtd html 3.2//', '-//w3c//dtd html 3.2s draft//', '-//w3c//dtd html 4.0 frameset//',
    '-//w3c//dtd html 4.0 transitional//', '-//w3c//dtd html experimental 19960712//',
    '-//w3c//dtd html experimental 970421//', '-//w3c//dtd w3 html//', '-//w3o//dtd w3 html 3.0//',
    '-//webtechs//dtd mozilla html 2.0//', '-//webtechs//dtd mozilla html//',
)
QUIRKS_NO_SYSTEM_PREFIXES = QUIRKS_PUBLIC_PREFIXES + ('-//w3c//dtd html 4.01 frameset//', '-//w3c//dtd html 4.01 transitional//')
QUIRKS_PUBLIC_IDS = frozenset(['-//w3o//dtd w3 html strict 3.0//en//', '-/w3c/dtd html 4.0 transitional/en', 'html'])
LIMITED_PREFIXES = ('-//w3c//dtd xhtml 1.0 frameset//', '-//w3c//dtd xhtml 1.0 transitional//')
LIMITED_WITH_SYSTEM_PREFIXES = LIMITED_PREFIXES + ('-//w3c//dtd html 4.01 frameset//', '-//w3c//dtd html 4.01 transitional//')
QUIRKS_SYSTEM_ID = 'http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd'


def doc_mode_for(tok):
    """parse5's getDocumentMode for a doctype token."""
    if tok.force_quirks:
        return 'quirks'
    if tok.name != 'html':
        return 'quirks'
    sid = tok.system_id
    if sid and sid.lower() == QUIRKS_SYSTEM_ID:
        return 'quirks'
    pid = tok.public_id
    if pid is not None:
        pid = pid.lower()
        if pid in QUIRKS_PUBLIC_IDS:
            return 'quirks'
        if pid.startswith(QUIRKS_NO_SYSTEM_PREFIXES if sid is None else QUIRKS_PUBLIC_PREFIXES):
            return 'quirks'
        if pid.startswith(LIMITED_PREFIXES if sid is None else LIMITED_WITH_SYSTEM_PREFIXES):
            return 'limited-quirks'
    return 'no-quirks'


# --------------------------------------------------------------------------- entities

_HTML5 = html.entities.html5
_LEGACY = sorted((k for k in _HTML5 if not k.endswith(';')), key=len, reverse=True)
_LEGACY_SET = frozenset(_LEGACY)
_MAX_LEGACY = max(len(k) for k in _LEGACY)
_C1 = {}
for _b in range(0x80, 0xA0):
    try:
        _C1[_b] = bytes([_b]).decode('cp1252')
    except UnicodeDecodeError:
        _C1[_b] = chr(_b)
_ENT_RE = re.compile(r'&(?:#[xX]([0-9a-fA-F]+);?|#([0-9]+);?|([A-Za-z][A-Za-z0-9]*)(;?))')


def _chr16(cp):
    if cp == 0 or cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
        return '�'
    if cp in _C1:
        return _C1[cp]
    if cp > 0xFFFF:
        cp -= 0x10000
        return chr(0xD800 + (cp >> 10)) + chr(0xDC00 + (cp & 0x3FF))
    return chr(cp)


def decode_entities(s, in_attr=False):
    """Decode HTML character references the way the HTML tokenizer does."""
    if '&' not in s:
        return s
    out = []
    pos = 0
    n = len(s)
    for m in _ENT_RE.finditer(s):
        if m.start() < pos:
            continue
        out.append(s[pos:m.start()])
        if m.group(1) is not None:
            out.append(_chr16(int(m.group(1), 16)))
            pos = m.end()
        elif m.group(2) is not None:
            out.append(_chr16(int(m.group(2))))
            pos = m.end()
        else:
            name = m.group(3)
            semi = m.group(4)
            if semi and (name + ';') in _HTML5:
                out.append(to16(_HTML5[name + ';']))
                pos = m.end()
                continue
            # legacy references work without the semicolon: longest known prefix of the name
            hit = None
            for k in range(min(len(name), _MAX_LEGACY), 1, -1):
                if name[:k] in _LEGACY_SET:
                    hit = name[:k]
                    break
            if hit is None:
                out.append(m.group())
                pos = m.end()
                continue
            end = m.start() + 1 + len(hit)
            nxt = s[end] if end < n else ''
            if in_attr and (nxt == '=' or re.match(r'[A-Za-z0-9]', nxt or ' ')):
                out.append(m.group())
                pos = m.end()
                continue
            out.append(to16(_HTML5[hit]))
            pos = end  # remaining letters (and ';') stay as text
    out.append(s[pos:])
    return ''.join(out)


# --------------------------------------------------------------------------- tokenizer

HTML_WS = '\t\n\f '
_RUN_RE = re.compile(r'[\t\n\f ]+|[^\t\n\f ]+')
_OPENER_RE = re.compile(r'<(?=[A-Za-z!?/])')
_ATTR_NAME_RE = re.compile(r'=?[^\t\n\f />=]*')
_WS_RE = re.compile(r'[\t\n\f ]*')
_UNQUOTED_RE = re.compile(r'[^\t\n\f >]*')
_TAGNAME_RE = re.compile(r'[^\t\n\f />]*')
_COMMENT_END_RE = re.compile(r'--!?>')
_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}


def ascii_lower(s):
    return s.translate(_ASCII_LOWER)


def _unterminated_comment(s):
    """Comment text when the input ends inside a comment (trailing '-', '--', '--!' are not data)."""
    data = []
    st = 0
    for ch in s:
        if st == 0:
            if ch == '-':
                st = 1
            else:
                data.append(ch)
        elif st == 1:
            if ch == '-':
                st = 2
            else:
                data.append('-' + ch)
                st = 0
        elif st == 2:
            if ch == '!':
                st = 3
            elif ch == '-':
                data.append('-')
            else:
                data.append('--' + ch)
                st = 0
        else:
            if ch == '-':
                data.append('--!')
                st = 1
            else:
                data.append('--!' + ch)
                st = 0
    return ''.join(data)


class Token(object):
    __slots__ = (
        'type', 'name', 'tid', 'attrs', 'self_closing', 'data', 'start', 'end', 'sline', 'eline',
        'public_id', 'system_id', 'force_quirks',
    )

    def __init__(self, type_, **kw):
        self.type = type_
        self.name = None
        self.tid = None
        self.attrs = []
        self.self_closing = False
        self.data = ''
        self.start = 0
        self.end = 0
        self.sline = 1
        self.eline = 1
        self.public_id = None
        self.system_id = None
        self.force_quirks = False
        for k, v in kw.items():
            setattr(self, k, v)


def get_attr(token, name):
    for a in token.attrs:
        if a[0] == name:
            return a[1]
    return None


_END_TAG_RES = {}


def _end_tag_re(name):
    r = _END_TAG_RES.get(name)
    if r is None:
        r = _END_TAG_RES[name] = re.compile('</' + re.escape(name) + '(?=[\t\n\f />])', re.I | re.A)
    return r


class Tokenizer(object):
    def __init__(self, html_text, parser):
        self.html = html_text
        self.n = len(html_text)
        self.pos = 0
        self.parser = parser
        self.state = 'data'  # data | rcdata | rawtext | script | plaintext
        self.last_start_tag = ''
        self.queue = []
        self.nl = [m.start() for m in re.finditer('\n', html_text)]
        # parse5 quirk: a newline right after a '&' in character data is counted twice in its line
        # numbering (the tokenizer rewinds without cancelling the pending line increment). Mirror it.
        self.qs = []

    def line(self, p):
        """Line number parse5 reports while its read position is on character index p."""
        return bisect.bisect_left(self.nl, p) + 1 + bisect.bisect_right(self.qs, p)

    def _note_amp_newlines(self, raw, base):
        i = raw.find('&\n')
        while i >= 0:
            self.qs.append(base + i + 1)
            i = raw.find('&\n', i + 1)

    # ---- helpers
    def _text_tokens(self, a, b, decode, in_attr=False):
        """Queue character tokens for raw source html[a:b], split into whitespace / other runs."""
        raw = self.html[a:b]
        if decode and '&\n' in raw:
            self._note_amp_newlines(raw, a)
        for m in _RUN_RE.finditer(raw):
            seg = m.group()
            ws = seg[0] in HTML_WS
            data = seg
            if decode and '&' in data:
                data = decode_entities(data)
            if '\x00' in data:
                data = data.replace('\x00', '')
                if not data:
                    continue
            s = a + m.start()
            e = a + m.end()
            self.queue.append(Token('ws' if ws else 'char', data=data, start=s, end=e, sline=self.line(s), eline=self.line(max(e - 1, s))))

    def _scan_tag(self, k):
        """Scan attributes from index k (after the tag name). Returns (attrs, self_closing, end) or None at EOF."""
        h = self.html
        n = self.n
        attrs = []
        seen = set()
        while True:
            k = _WS_RE.match(h, k).end()
            if k >= n:
                return None
            c = h[k]
            if c == '>':
                return attrs, False, k + 1
            if c == '/':
                if k + 1 < n and h[k + 1] == '>':
                    return attrs, True, k + 2
                k += 1
                continue
            m = _ATTR_NAME_RE.match(h, k)
            name = ascii_lower(m.group())
            k = m.end()
            k = _WS_RE.match(h, k).end()
            value = ''
            if k < n and h[k] == '=':
                k = _WS_RE.match(h, k + 1).end()
                if k >= n:
                    return None
                q = h[k]
                if q == '"' or q == "'":
                    e = h.find(q, k + 1)
                    if e < 0:
                        self._note_amp_newlines(h[k + 1:], k + 1)  # the value runs to EOF
                        return None
                    vstart = k + 1
                    value = h[vstart:e]
                    k = e + 1
                else:
                    m2 = _UNQUOTED_RE.match(h, k)
                    vstart = k
                    value = m2.group()
                    k = m2.end()
                    if value.endswith('&') and k < n and h[k] == '\n':
                        self.qs.append(k)
                if '&' in value:
                    if '&\n' in value:
                        self._note_amp_newlines(value, vstart)
                    value = decode_entities(value, True)
                value = value.replace('\x00', '')
            if name not in seen:
                seen.add(name)
                attrs.append([name, value])

    def _script_end(self, i):
        """Index of the `</script` that really ends a script (handles <!-- ... --> escaping), or -1."""
        h = self.html
        n = self.n
        end_re = _end_tag_re('script')
        S, E, ED, EDD, DE, DED, DEDD = range(7)
        st = S
        pos = i
        while pos < n:
            if st == S:
                p = h.find('<', pos)
                if p < 0:
                    return -1
                if h.startswith('</', p):
                    if end_re.match(h, p):
                        return p
                    pos = p + 2
                elif h.startswith('<!--', p):
                    st = EDD
                    pos = p + 4
                else:
                    pos = p + 1
                continue
            c = h[pos]
            if st == E:
                if c == '-':
                    st = ED
                    pos += 1
                elif c == '<':
                    nx = h[pos + 1] if pos + 1 < n else ''
                    if nx == '/':
                        if end_re.match(h, pos):
                            return pos
                        pos += 2
                    elif nx and nx.isalpha() and nx < '\x80':
                        m = re.compile(r'[A-Za-z]+').match(h, pos + 1)
                        after = m.end()
                        if after < n and h[after] in '\t\n\f />':
                            st = DE if m.group().lower() == 'script' else E
                            pos = after + 1
                        else:
                            pos = after
                    else:
                        pos += 1
                else:
                    pos += 1
            elif st == ED:
                if c == '-':
                    st = EDD
                    pos += 1
                elif c == '<':
                    st = E
                else:
                    st = E
                    pos += 1
            elif st == EDD:
                if c == '-':
                    pos += 1
                elif c == '<':
                    st = E
                elif c == '>':
                    st = S
                    pos += 1
                else:
                    st = E
                    pos += 1
            elif st == DE:
                if c == '-':
                    st = DED
                    pos += 1
                elif c == '<':
                    nx = h[pos + 1] if pos + 1 < n else ''
                    if nx == '/':
                        m = re.compile(r'[A-Za-z]*').match(h, pos + 2)
                        after = m.end()
                        if m.group() and after < n and h[after] in '\t\n\f />':
                            if m.group().lower() == 'script':
                                st = E
                            pos = after + 1
                        else:
                            pos = after
                    else:
                        pos += 1
                else:
                    pos += 1
            elif st == DED:
                if c == '-':
                    st = DEDD
                    pos += 1
                elif c == '<':
                    st = DE
                else:
                    st = DE
                    pos += 1
            else:  # DEDD
                if c == '-':
                    pos += 1
                elif c == '<':
                    st = DE
                elif c == '>':
                    st = S
                    pos += 1
                else:
                    st = DE
                    pos += 1
        return -1

    def _raw_text(self):
        """Raw text / RCDATA / script content up to the appropriate end tag (or EOF)."""
        i = self.pos
        if self.state == 'plaintext':
            end = self.n
        elif self.state == 'script':
            end = self._script_end(i)
            if end < 0:
                end = self.n
        else:
            m = _end_tag_re(self.last_start_tag).search(self.html, i)
            end = m.start() if m else self.n
        if end > i:
            self._text_tokens(i, end, self.state == 'rcdata')
        self.pos = end
        if end < self.n:
            self.state = 'data'

    def next_token(self):
        if self.queue:
            return self.queue.pop(0)
        if self.pos >= self.n:
            return Token('eof', start=self.n, end=self.n, sline=self.line(self.n), eline=self.line(self.n))
        if self.state != 'data':
            before = self.pos
            self._raw_text()
            if self.queue:
                return self.queue.pop(0)
            if self.pos == before and self.pos < self.n and self.state == 'data':
                pass  # zero-length text, continue below in data state
            elif self.pos >= self.n:
                return Token('eof', start=self.n, end=self.n, sline=self.line(self.n), eline=self.line(self.n))
        h = self.html
        i = self.pos
        m = _OPENER_RE.search(h, i)
        # a trailing "</" at EOF is just text
        j = m.start() if m else self.n
        if m and h[j + 1] == '/' and j + 2 >= self.n:
            j = self.n
        if j > i:
            self._text_tokens(i, j, True)
            self.pos = j
            return self.queue.pop(0)
        # j == i: a markup opener
        c = h[i + 1]
        if c == '!':
            return self._markup_declaration(i)
        if c == '?':
            return self._bogus_comment(i, i + 1)
        if c == '/':
            nx = h[i + 2] if i + 2 < self.n else ''
            if nx.isalpha() and nx < '\x80':
                return self._tag(i, i + 2, False)
            if nx == '>':
                self.pos = i + 3
                return self.next_token()
            return self._bogus_comment(i, i + 2)
        return self._tag(i, i + 1, True)

    def _tag(self, i, name_start, is_start):
        h = self.html
        m = _TAGNAME_RE.match(h, name_start)
        name = ascii_lower(m.group()).replace('\x00', '�')
        res = self._scan_tag(m.end())
        if res is None:
            self.pos = self.n
            return Token('eof', start=self.n, end=self.n, sline=self.line(self.n), eline=self.line(self.n))
        attrs, selfc, end = res
        self.pos = end
        tok = Token('start' if is_start else 'end', name=name, start=i, end=end, sline=self.line(i), eline=self.line(end - 1))
        tok.tid = name
        if is_start:
            tok.attrs = attrs
            tok.self_closing = selfc
            self.last_start_tag = name
        return tok

    def _bogus_comment(self, i, data_start):
        h = self.html
        e = h.find('>', data_start)
        if e < 0:
            data = h[data_start:]
            end = self.n
        else:
            data = h[data_start:e]
            end = e + 1
        self.pos = end
        return Token('comment', data=data.replace('\x00', '�'), start=i, end=end, sline=self.line(i), eline=self.line(end - 1))

    def _markup_declaration(self, i):
        h = self.html
        if h.startswith('<!--', i):
            k = i + 4
            if h.startswith('>', k):
                end, data = k + 1, ''
            elif h.startswith('->', k):
                end, data = k + 2, ''
            else:
                m = _COMMENT_END_RE.search(h, k)
                if m:
                    data, end = h[k:m.start()], m.end()
                else:
                    data, end = _unterminated_comment(h[k:]), self.n
            self.pos = end
            return Token('comment', data=data, start=i, end=end, sline=self.line(i), eline=self.line(end - 1))
        if h[i + 2:i + 9].lower() == 'doctype':
            return self._doctype(i)
        if h.startswith('<![CDATA[', i) and self.parser.in_foreign_node():
            e = h.find(']]>', i + 9)
            if e < 0:
                text_end, end = self.n, self.n
            else:
                text_end, end = e, e + 3
            self.pos = end
            self.queue = []
            if text_end > i + 9:
                self._text_tokens(i + 9, text_end, False)
            if self.queue:
                return self.queue.pop(0)
            return self.next_token()
        return self._bogus_comment(i, i + 2)

    def _doctype(self, i):
        h = self.html
        n = self.n
        k = i + 9
        tok = Token('doctype', start=i)

        def finish(end):
            self.pos = end
            tok.end = end
            tok.sline = self.line(i)
            tok.eline = self.line(end - 1)
            return tok

        def skip_bogus(k):
            e = h.find('>', k)
            return n if e < 0 else e + 1

        k = _WS_RE.match(h, k).end()
        if k >= n:
            tok.force_quirks = True
            return finish(n)
        if h[k] == '>':
            tok.force_quirks = True
            return finish(k + 1)
        m = re.compile(r'[^\t\n\f >]*').match(h, k)
        tok.name = ascii_lower(m.group()).replace('\x00', '�')
        k = _WS_RE.match(h, m.end()).end()
        if k >= n:
            tok.force_quirks = True
            return finish(n)
        if h[k] == '>':
            return finish(k + 1)
        kw = h[k:k + 6].lower()
        if kw not in ('public', 'system'):
            tok.force_quirks = True
            return finish(skip_bogus(k))
        k += 6

        def read_id(k):
            """After the keyword: whitespace then a quoted identifier. Returns (value|None, k, ok)."""
            k = _WS_RE.match(h, k).end()
            if k >= n:
                return None, n, False
            q = h[k]
            if q not in '"\'':
                return None, k, False
            e = h.find(q, k + 1)
            gt = h.find('>', k + 1)
            if e < 0 or (0 <= gt < e):
                # abrupt end of the identifier at '>' (or EOF)
                if e < 0 and gt < 0:
                    return h[k + 1:], n, False
                return h[k + 1:gt], gt + 1, 'abrupt'
            return h[k + 1:e], e + 1, True

        if kw == 'public':
            val, k, ok = read_id(k)
            if ok == 'abrupt':
                tok.public_id = val
                tok.force_quirks = True
                return finish(k)
            if not ok:
                tok.force_quirks = True
                if val is not None:
                    tok.public_id = val
                return finish(skip_bogus(k) if k < n else n)
            tok.public_id = val
            k = _WS_RE.match(h, k).end()
            if k >= n:
                tok.force_quirks = True
                return finish(n)
            if h[k] == '>':
                return finish(k + 1)
            if h[k] in '"\'':
                val, k, ok = read_id(k)
                if ok == 'abrupt':
                    tok.system_id = val
                    tok.force_quirks = True
                    return finish(k)
                if not ok:
                    tok.force_quirks = True
                    if val is not None:
                        tok.system_id = val
                    return finish(n if k >= n else skip_bogus(k))
                tok.system_id = val
                k = _WS_RE.match(h, k).end()
                if k < n and h[k] == '>':
                    return finish(k + 1)
                return finish(skip_bogus(k))  # junk after the system id: bogus doctype (no force-quirks)
            tok.force_quirks = True
            return finish(skip_bogus(k))
        # SYSTEM
        val, k, ok = read_id(k)
        if ok == 'abrupt':
            tok.system_id = val
            tok.force_quirks = True
            return finish(k)
        if not ok:
            tok.force_quirks = True
            if val is not None:
                tok.system_id = val
            return finish(n if k >= n else skip_bogus(k))
        tok.system_id = val
        k = _WS_RE.match(h, k).end()
        if k < n and h[k] == '>':
            return finish(k + 1)
        return finish(skip_bogus(k))


# --------------------------------------------------------------------------- parser

(INITIAL, BEFORE_HTML, BEFORE_HEAD, IN_HEAD, IN_HEAD_NO_SCRIPT, AFTER_HEAD, IN_BODY, TEXT, IN_TABLE, IN_TABLE_TEXT,
 IN_CAPTION, IN_COLUMN_GROUP, IN_TABLE_BODY, IN_ROW, IN_CELL, IN_SELECT, IN_SELECT_IN_TABLE, IN_TEMPLATE, AFTER_BODY,
 IN_FRAMESET, AFTER_FRAMESET, AFTER_AFTER_BODY, AFTER_AFTER_FRAMESET) = range(23)

_MARKER = object()


class _Entry(object):
    __slots__ = ('element', 'token')

    def __init__(self, element, token):
        self.element = element
        self.token = token


class Parser(object):
    def __init__(self):
        self.document = Fragment()
        self.stack = []
        self.tmpl_count = 0
        self.mode = INITIAL
        self.orig_mode = INITIAL
        self.head_element = None
        self.form_element = None
        self.tmpl_modes = []
        self.pending_chars = []
        self.has_nonws_pending = False
        self.frameset_ok = True
        self.skip_nl = False
        self.foster = False
        self.current_token = None
        self.afe = []  # active formatting elements, newest first
        self.bookmark = None
        self.stopped = False
        self.tokenizer = None

    # ---- stack helpers
    @property
    def current(self):
        return self.stack[-1] if self.stack else self.document

    @property
    def current_tid(self):
        return self.stack[-1].tid if self.stack else None

    def push(self, el):
        self.stack.append(el)
        if el.tid == 'template' and el.ns == NS_HTML:
            self.tmpl_count += 1

    def pop(self):
        el = self.stack.pop()
        if self.tmpl_count > 0 and el.tid == 'template' and el.ns == NS_HTML:
            self.tmpl_count -= 1
        self._set_end_location(el, self.current_token)
        return el

    def in_foreign_node(self):
        if not self.stack:
            return False
        cur = self.stack[-1]
        if len(self.stack) == 1 or cur.ns == NS_HTML:
            return False
        return not self._is_integration_point(cur.tid, cur)

    def current_not_in_html(self):
        return bool(self.stack) and self.stack[-1].ns != NS_HTML

    def shorten_to_length(self, idx):
        while len(self.stack) > idx:
            self.pop()

    def index_of(self, el):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i] is el:
                return i
        return -1

    def contains(self, el):
        return self.index_of(el) > -1

    def remove_from_stack(self, el):
        idx = self.index_of(el)
        if idx >= 0:
            if idx == len(self.stack) - 1:
                self.pop()
            else:
                del self.stack[idx]
                if el.tid == 'template' and el.ns == NS_HTML and self.tmpl_count > 0:
                    self.tmpl_count -= 1
                self._set_end_location(el, self.current_token)

    def pop_until_tag_popped(self, tid):
        i = len(self.stack)
        while True:
            i = self._last_index_of_tid(tid, i - 1)
            if not (i > 0 and self.stack[i].ns != NS_HTML):
                break
        self.shorten_to_length(max(i, 0))

    def _last_index_of_tid(self, tid, frm):
        for i in range(min(frm, len(self.stack) - 1), -1, -1):
            if self.stack[i].tid == tid:
                return i
        return -1

    def pop_until_popped(self, tids, ns):
        self.shorten_to_length(max(self._index_of_tids(tids, ns), 0))

    def _index_of_tids(self, tids, ns):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].tid in tids and self.stack[i].ns == ns:
                return i
        return -1

    def clear_back_to(self, tids):
        idx = self._index_of_tids(tids, NS_HTML)
        self.shorten_to_length(idx + 1)

    def has_in_dynamic_scope(self, tid, html_scope):
        for i in range(len(self.stack) - 1, -1, -1):
            el = self.stack[i]
            if el.ns == NS_HTML:
                if el.tid == tid:
                    return True
                if el.tid in html_scope:
                    return False
            elif el.ns == NS_SVG:
                if el.tid in SCOPING_SVG:
                    return False
            elif el.ns == NS_MATHML:
                if el.tid in SCOPING_MATHML:
                    return False
        return True

    def has_in_scope(self, tid):
        return self.has_in_dynamic_scope(tid, SCOPING_HTML)

    def has_in_list_item_scope(self, tid):
        return self.has_in_dynamic_scope(tid, SCOPING_HTML_LIST)

    def has_in_button_scope(self, tid):
        return self.has_in_dynamic_scope(tid, SCOPING_HTML_BUTTON)

    def has_numbered_header_in_scope(self):
        for i in range(len(self.stack) - 1, -1, -1):
            el = self.stack[i]
            if el.ns == NS_HTML:
                if el.tid in NUMBERED_HEADERS:
                    return True
                if el.tid in SCOPING_HTML:
                    return False
            elif el.ns == NS_SVG:
                if el.tid in SCOPING_SVG:
                    return False
            elif el.ns == NS_MATHML:
                if el.tid in SCOPING_MATHML:
                    return False
        return True

    def has_in_table_scope(self, tid):
        for i in range(len(self.stack) - 1, -1, -1):
            el = self.stack[i]
            if el.ns != NS_HTML:
                continue
            if el.tid == tid:
                return True
            if el.tid == 'table' or el.tid == 'html':
                return False
        return True

    def has_table_body_context_in_table_scope(self):
        for i in range(len(self.stack) - 1, -1, -1):
            el = self.stack[i]
            if el.ns != NS_HTML:
                continue
            if el.tid in ('tbody', 'thead', 'tfoot'):
                return True
            if el.tid == 'table' or el.tid == 'html':
                return False
        return True

    def has_in_select_scope(self, tid):
        for i in range(len(self.stack) - 1, -1, -1):
            el = self.stack[i]
            if el.ns != NS_HTML:
                continue
            if el.tid == tid:
                return True
            if el.tid in ('option', 'optgroup'):
                continue
            return False
        return True

    def generate_implied_end_tags(self):
        while self.stack and self.stack[-1].tid in IMPLICIT_END:
            self.pop()

    def generate_implied_end_tags_thoroughly(self):
        while self.stack and self.stack[-1].tid in IMPLICIT_END_THOROUGH:
            self.pop()

    def generate_implied_end_tags_with_exclusion(self, excl):
        while self.stack and self.stack[-1].tid != excl and self.stack[-1].tid in IMPLICIT_END_THOROUGH:
            self.pop()

    def try_peek_body(self):
        return self.stack[1] if len(self.stack) >= 2 and self.stack[1].tid == 'body' else None

    def pop_all_up_to_html(self):
        self.tmpl_count = 0
        self.shorten_to_length(1)

    # ---- locations
    def _set_end_location(self, el, closing):
        if el.has_loc and closing is not None:
            if closing.type == 'end' and closing.name == el.name:
                el.end_line = closing.eline
                el.end_tag = True
            else:
                el.end_line = closing.sline

    # ---- tree mutation
    def _attach(self, el, tok):
        if tok is not None:
            el.has_loc = True
            el.start_line = tok.sline
            el.end_line = tok.eline  # end of the start tag until a real end location is known
        if self._should_foster():
            self._foster_parent_element(el)
        else:
            _append(self._cur_tmpl_content_or_node(), el)

    def _cur_tmpl_content_or_node(self):
        if not self.stack:
            return self.document
        cur = self.stack[-1]
        if cur.tid == 'template' and cur.ns == NS_HTML:
            return cur.children[0]
        return cur

    def append_element(self, tok, ns):
        el = Element(tok.name, ns, tok.attrs)
        el.tid = tok.tid if tok.tid is not None else tok.name
        self._attach(el, tok)

    def insert_element(self, tok, ns):
        el = Element(tok.name, ns, tok.attrs)
        el.tid = tok.tid if tok.tid is not None else tok.name
        self._attach(el, tok)
        self.push(el)

    def insert_fake(self, name):
        el = Element(name, NS_HTML, [])
        self._attach(el, None)
        self.push(el)

    def insert_template(self, tok):
        el = Element(tok.name, NS_HTML, tok.attrs)
        content = Fragment()
        _append(el, content)
        self._attach(el, tok)
        self.push(el)

    def insert_fake_root(self):
        el = Element('html', NS_HTML, [])
        _append(self.current, el)
        self.push(el)

    def append_comment(self, tok, parent):
        _append(parent, Comment(tok.data))

    def insert_characters(self, tok):
        chars = tok.data
        if self._should_foster():
            parent, before = self._find_foster_location()
            if before is not None:
                idx = _index_of(parent, before)
                prev = parent.children[idx - 1] if idx > 0 else None
                if isinstance(prev, Text):
                    prev.data += chars
                else:
                    _insert_before(parent, Text(chars), before)
            else:
                self._insert_text(parent, chars)
        else:
            self._insert_text(self._cur_tmpl_content_or_node(), chars)

    @staticmethod
    def _insert_text(parent, chars):
        last = parent.children[-1] if parent.children else None
        if isinstance(last, Text):
            last.data += chars
        else:
            _append(parent, Text(chars))

    def adopt_nodes(self, donor, recipient):
        while donor.children:
            child = donor.children[0]
            _detach(child)
            _append(recipient, child)

    @staticmethod
    def adopt_attributes(recipient, attrs):
        for a in attrs:
            if a[0] not in recipient.attrs:
                recipient.attrs[a[0]] = a[1]

    # ---- foster parenting
    def _should_foster(self):
        return self.foster and bool(self.stack) and self.stack[-1].tid in TABLE_STRUCTURE

    def _find_foster_location(self):
        for i in range(len(self.stack) - 1, -1, -1):
            el = self.stack[i]
            if el.tid == 'template':
                if el.ns == NS_HTML:
                    return el.children[0], None
            elif el.tid == 'table':
                if el.parent is not None:
                    return el.parent, el
                return self.stack[i - 1], None
        return self.stack[0], None

    def _foster_parent_element(self, el):
        parent, before = self._find_foster_location()
        if before is not None:
            _insert_before(parent, el, before)
        else:
            _append(parent, el)

    def is_special(self, el):
        if el.ns == NS_HTML:
            return el.tid in SPECIAL_HTML
        if el.ns == NS_MATHML:
            return el.tid in SPECIAL_MATHML
        return el.tid in SPECIAL_SVG

    # ---- integration points
    def _is_integration_point(self, tid, el, foreign_ns=None):
        ns = el.ns
        if foreign_ns is None or foreign_ns == NS_HTML:
            if ns == NS_MATHML and tid == 'annotation-xml':
                v = el.attrs.get('encoding')
                if v is not None:
                    v = v.lower()
                    return v == 'text/html' or v == 'application/xhtml+xml'
            if ns == NS_SVG and tid in ('foreignObject', 'desc', 'title'):
                return True
        if foreign_ns is None or foreign_ns == NS_MATHML:
            if ns == NS_MATHML and tid in ('mi', 'mo', 'mn', 'ms', 'mtext'):
                return True
        return False

    # ---- formatting elements
    def reconstruct_afe(self):
        if not self.afe:
            return
        end_index = -1
        for i, e in enumerate(self.afe):
            if e is _MARKER or self.contains(e.element):
                end_index = i
                break
        unopen = len(self.afe) - 1 if end_index == -1 else end_index - 1
        for i in range(unopen, -1, -1):
            e = self.afe[i]
            self.insert_element(e.token, e.element.ns)
            e.element = self.current

    def afe_clear_to_last_marker(self):
        for i, e in enumerate(self.afe):
            if e is _MARKER:
                del self.afe[:i + 1]
                return
        del self.afe[:]

    def afe_find_in_scope(self, name):
        for e in self.afe:
            if e is _MARKER:
                return None
            if e.element.name == name:
                return e
        return None

    def afe_get_entry(self, el):
        for e in self.afe:
            if e is not _MARKER and e.element is el:
                return e
        return None

    def afe_push(self, el, tok):
        # Noah's Ark clause
        if len(self.afe) >= 3:
            cands = []
            for i, e in enumerate(self.afe):
                if e is _MARKER:
                    break
                if e.element.name == el.name and e.element.ns == el.ns and len(e.element.attrs) == len(el.attrs):
                    cands.append((i, e.element.attrs))
            if len(cands) >= 3:
                valid = 0
                removed = []
                for idx, attrs in cands:
                    if all(k in el.attrs and el.attrs[k] == v for k, v in attrs.items()):
                        valid += 1
                        if valid >= 3:
                            removed.append(idx)
                # JS splices while iterating by candidate index (indexes shift): mimic by removing one at a time
                shift = 0
                for idx in removed:
                    del self.afe[idx - shift]
                    shift += 1
        self.afe.insert(0, _Entry(el, tok))

    def afe_remove(self, entry):
        for i, e in enumerate(self.afe):
            if e is entry:
                del self.afe[i]
                return

    # ---- closing helpers
    def close_table_cell(self):
        self.generate_implied_end_tags()
        self.pop_until_popped(TABLE_CELLS, NS_HTML)
        self.afe_clear_to_last_marker()
        self.mode = IN_ROW

    def close_p(self):
        self.generate_implied_end_tags_with_exclusion('p')
        self.pop_until_tag_popped('p')

    def reset_insertion_mode(self):
        for i in range(len(self.stack) - 1, -1, -1):
            tid = self.stack[i].tid
            if tid == 'tr':
                self.mode = IN_ROW
                return
            if tid in ('tbody', 'thead', 'tfoot'):
                self.mode = IN_TABLE_BODY
                return
            if tid == 'caption':
                self.mode = IN_CAPTION
                return
            if tid == 'colgroup':
                self.mode = IN_COLUMN_GROUP
                return
            if tid == 'table':
                self.mode = IN_TABLE
                return
            if tid == 'body':
                self.mode = IN_BODY
                return
            if tid == 'frameset':
                self.mode = IN_FRAMESET
                return
            if tid == 'select':
                self._reset_for_select(i)
                return
            if tid == 'template':
                self.mode = self.tmpl_modes[0]
                return
            if tid == 'html':
                self.mode = AFTER_HEAD if self.head_element is not None else BEFORE_HEAD
                return
            if tid in ('td', 'th') and i > 0:
                self.mode = IN_CELL
                return
            if tid == 'head' and i > 0:
                self.mode = IN_HEAD
                return
        self.mode = IN_BODY

    def _reset_for_select(self, select_idx):
        if select_idx > 0:
            for i in range(select_idx - 1, 0, -1):
                tid = self.stack[i].tid
                if tid == 'template':
                    break
                if tid == 'table':
                    self.mode = IN_SELECT_IN_TABLE
                    return
        self.mode = IN_SELECT

    # ---- tokenizer control
    def switch_to_text(self, tok, state):
        self.insert_element(tok, NS_HTML)
        self.tokenizer.state = state
        self.orig_mode = self.mode
        self.mode = TEXT

    # ---- token entry points
    def on_start_tag(self, tok):
        self.skip_nl = False
        self.current_token = tok
        self.process_start_tag(tok)

    def on_end_tag(self, tok):
        self.skip_nl = False
        self.current_token = tok
        if self.current_not_in_html():
            end_tag_in_foreign(self, tok)
        else:
            self.end_tag_outside_foreign(tok)

    def process_token(self, tok):
        t = tok.type
        if t == 'char':
            self.on_character(tok)
        elif t == 'ws':
            self.on_whitespace(tok)
        elif t == 'comment':
            self.on_comment(tok)
        elif t == 'doctype':
            self.on_doctype(tok)
        elif t == 'start':
            self.process_start_tag(tok)
        elif t == 'end':
            self.on_end_tag(tok)
        elif t == 'eof':
            self.on_eof(tok)

    def run(self, tokenizer):
        self.tokenizer = tokenizer
        while not self.stopped:
            tok = tokenizer.next_token()
            t = tok.type
            if t == 'char':
                self.on_character(tok)
            elif t == 'ws':
                self.on_whitespace(tok)
            elif t == 'comment':
                self.on_comment(tok)
            elif t == 'doctype':
                self.on_doctype(tok)
            elif t == 'start':
                self.on_start_tag(tok)
            elif t == 'end':
                self.on_end_tag(tok)
            else:
                self.on_eof(tok)
                break

    def on_character(self, tok):
        self.skip_nl = False
        if self.in_foreign_node():
            self.insert_characters(tok)
            self.frameset_ok = False
            return
        m = self.mode
        if m == INITIAL:
            token_in_initial(self, tok)
        elif m == BEFORE_HTML:
            token_before_html(self, tok)
        elif m == BEFORE_HEAD:
            token_before_head(self, tok)
        elif m == IN_HEAD:
            token_in_head(self, tok)
        elif m == AFTER_HEAD:
            token_after_head(self, tok)
        elif m in (IN_BODY, IN_CAPTION, IN_CELL, IN_TEMPLATE):
            character_in_body(self, tok)
        elif m in (TEXT, IN_SELECT, IN_SELECT_IN_TABLE):
            self.insert_characters(tok)
        elif m in (IN_TABLE, IN_TABLE_BODY, IN_ROW):
            character_in_table(self, tok)
        elif m == IN_TABLE_TEXT:
            self.pending_chars.append(tok)
            self.has_nonws_pending = True
        elif m == IN_COLUMN_GROUP:
            token_in_column_group(self, tok)
        elif m == AFTER_BODY:
            token_after_body(self, tok)
        elif m == AFTER_AFTER_BODY:
            token_after_after_body(self, tok)

    def on_whitespace(self, tok):
        if self.skip_nl:
            self.skip_nl = False
            if tok.data[:1] == '\n':
                if len(tok.data) == 1:
                    return
                tok.data = tok.data[1:]
        if self.in_foreign_node():
            self.insert_characters(tok)
            return
        m = self.mode
        if m in (IN_HEAD, IN_HEAD_NO_SCRIPT, AFTER_HEAD, TEXT, IN_COLUMN_GROUP, IN_SELECT, IN_SELECT_IN_TABLE, IN_FRAMESET, AFTER_FRAMESET):
            self.insert_characters(tok)
        elif m in (IN_BODY, IN_CAPTION, IN_CELL, IN_TEMPLATE, AFTER_BODY, AFTER_AFTER_BODY, AFTER_AFTER_FRAMESET):
            whitespace_in_body(self, tok)
        elif m in (IN_TABLE, IN_TABLE_BODY, IN_ROW):
            character_in_table(self, tok)
        elif m == IN_TABLE_TEXT:
            self.pending_chars.append(tok)

    def on_comment(self, tok):
        self.skip_nl = False
        if self.current_not_in_html():
            self.append_comment(tok, self._cur_tmpl_content_or_node())
            return
        m = self.mode
        if m in (INITIAL, BEFORE_HTML, BEFORE_HEAD, IN_HEAD, IN_HEAD_NO_SCRIPT, AFTER_HEAD, IN_BODY, IN_TABLE, IN_CAPTION,
                 IN_COLUMN_GROUP, IN_TABLE_BODY, IN_ROW, IN_CELL, IN_SELECT, IN_SELECT_IN_TABLE, IN_TEMPLATE, IN_FRAMESET, AFTER_FRAMESET):
            self.append_comment(tok, self._cur_tmpl_content_or_node())
        elif m == IN_TABLE_TEXT:
            token_in_table_text(self, tok)
        elif m == AFTER_BODY:
            self.append_comment(tok, self.stack[0])
        elif m in (AFTER_AFTER_BODY, AFTER_AFTER_FRAMESET):
            self.append_comment(tok, self.document)

    def on_doctype(self, tok):
        self.skip_nl = False
        if self.mode == INITIAL:
            self.document.doctype = tok
            self.document.doc_mode = doc_mode_for(tok)
            self.mode = BEFORE_HTML
        elif self.mode == IN_TABLE_TEXT:
            token_in_table_text(self, tok)

    def process_start_tag(self, tok):
        if self.should_process_start_in_foreign(tok):
            start_tag_in_foreign(self, tok)
        else:
            self.start_tag_outside_foreign(tok)

    def should_process_start_in_foreign(self, tok):
        if not self.current_not_in_html():
            return False
        cur = self.stack[-1]
        if tok.tid == 'svg' and cur.name == 'annotation-xml' and cur.ns == NS_MATHML:
            return False
        return self.in_foreign_node() or (tok.tid in ('mglyph', 'malignmark') and not self._is_integration_point(cur.tid, cur, NS_HTML))

    def start_tag_outside_foreign(self, tok):
        m = self.mode
        fn = START_TAG_MODES.get(m)
        if fn is not None:
            fn(self, tok)

    def end_tag_outside_foreign(self, tok):
        m = self.mode
        fn = END_TAG_MODES.get(m)
        if fn is not None:
            fn(self, tok)

    def on_eof(self, tok):
        m = self.mode
        if m == INITIAL:
            token_in_initial(self, tok)
        elif m == BEFORE_HTML:
            token_before_html(self, tok)
        elif m == BEFORE_HEAD:
            token_before_head(self, tok)
        elif m == IN_HEAD:
            token_in_head(self, tok)
        elif m == IN_HEAD_NO_SCRIPT:
            token_in_head_no_script(self, tok)
        elif m == AFTER_HEAD:
            token_after_head(self, tok)
        elif m in (IN_BODY, IN_TABLE, IN_CAPTION, IN_COLUMN_GROUP, IN_TABLE_BODY, IN_ROW, IN_CELL, IN_SELECT, IN_SELECT_IN_TABLE):
            eof_in_body(self, tok)
        elif m == TEXT:
            eof_in_text(self, tok)
        elif m == IN_TABLE_TEXT:
            token_in_table_text(self, tok)
        elif m == IN_TEMPLATE:
            eof_in_template(self, tok)
        else:
            stop_parsing(self, tok)


# --------------------------------------------------------------------------- adoption agency

def aa_obtain_formatting_entry(p, tok):
    entry = p.afe_find_in_scope(tok.name)
    if entry is not None:
        if not p.contains(entry.element):
            p.afe_remove(entry)
            entry = None
        elif not p.has_in_scope(tok.tid):
            entry = None
    else:
        generic_end_tag_in_body(p, tok)
    return entry


def aa_obtain_furthest_block(p, entry):
    furthest = None
    idx = len(p.stack) - 1
    while idx >= 0:
        el = p.stack[idx]
        if el is entry.element:
            break
        if p.is_special(el):
            furthest = el
        idx -= 1
    if furthest is None:
        p.shorten_to_length(max(idx, 0))
        p.afe_remove(entry)
    return furthest


def common_ancestor(p, el):
    idx = p.index_of(el) - 1
    return p.stack[idx] if idx >= 0 else None


def aa_inner_loop(p, furthest, formatting_element):
    last = furthest
    nxt = common_ancestor(p, furthest)
    element = nxt
    i = 0
    while element is not formatting_element:
        nxt = common_ancestor(p, element)
        entry = p.afe_get_entry(element)
        overflow = entry is not None and i >= 3
        should_remove = entry is None or overflow
        if should_remove:
            if overflow:
                p.afe_remove(entry)
            p.remove_from_stack(element)
        else:
            element = aa_recreate_element(p, entry)
            if last is furthest:
                p.bookmark = entry
            _detach(last)
            _append(element, last)
            last = element
        i += 1
        element = nxt
    return last


def aa_recreate_element(p, entry):
    ns = entry.element.ns
    new = Element(entry.token.name, ns, entry.token.attrs)
    new.tid = entry.token.tid if entry.token.tid is not None else entry.token.name
    idx = p.index_of(entry.element)
    p.stack[idx] = new
    entry.element = new
    return new


def aa_insert_last_node(p, ancestor, last):
    if ancestor.tid in TABLE_STRUCTURE:
        p._foster_parent_element(last)
    else:
        if ancestor.tid == 'template' and ancestor.ns == NS_HTML:
            ancestor = ancestor.children[0]
        _append(ancestor, last)


def aa_replace_formatting_element(p, furthest, entry):
    tok = entry.token
    new = Element(tok.name, entry.element.ns, tok.attrs)
    new.tid = tok.tid if tok.tid is not None else tok.name
    p.adopt_nodes(furthest, new)
    _append(furthest, new)
    # insert after bookmark
    bi = -1
    for i, e in enumerate(p.afe):
        if e is p.bookmark:
            bi = i
            break
    p.afe.insert(bi, _Entry(new, tok))
    p.afe_remove(entry)
    p.remove_from_stack(entry.element)
    ref = p.index_of(furthest) + 1
    p.stack.insert(ref, new)
    if new.tid == 'template' and new.ns == NS_HTML:
        p.tmpl_count += 1


def call_adoption_agency(p, tok):
    for _ in range(8):
        entry = aa_obtain_formatting_entry(p, tok)
        if entry is None:
            break
        furthest = aa_obtain_furthest_block(p, entry)
        if furthest is None:
            break
        p.bookmark = entry
        last = aa_inner_loop(p, furthest, entry.element)
        ancestor = common_ancestor(p, entry.element)
        _detach(last)
        if ancestor is not None:
            aa_insert_last_node(p, ancestor, last)
        aa_replace_formatting_element(p, furthest, entry)


# --------------------------------------------------------------------------- generic handlers

def stop_parsing(p, tok):
    p.stopped = True
    target = 2
    for i in range(len(p.stack) - 1, target - 1, -1):
        p._set_end_location(p.stack[i], tok)
    if p.stack:
        html_el = p.stack[0]
        if html_el.has_loc and not html_el.end_tag:
            p._set_end_location(html_el, tok)
            if len(p.stack) >= 2:
                body = p.stack[1]
                if body.has_loc and not body.end_tag:
                    p._set_end_location(body, tok)


def token_in_initial(p, tok):
    p.document.doc_mode = 'quirks'
    p.mode = BEFORE_HTML
    p.process_token(tok)


def start_tag_before_html(p, tok):
    if tok.tid == 'html':
        p.insert_element(tok, NS_HTML)
        p.mode = BEFORE_HEAD
    else:
        token_before_html(p, tok)


def end_tag_before_html(p, tok):
    if tok.tid in ('html', 'head', 'body', 'br'):
        token_before_html(p, tok)


def token_before_html(p, tok):
    p.insert_fake_root()
    p.mode = BEFORE_HEAD
    p.process_token(tok)


def start_tag_before_head(p, tok):
    if tok.tid == 'html':
        start_tag_in_body(p, tok)
    elif tok.tid == 'head':
        p.insert_element(tok, NS_HTML)
        p.head_element = p.current
        p.mode = IN_HEAD
    else:
        token_before_head(p, tok)


def end_tag_before_head(p, tok):
    if tok.tid in ('head', 'body', 'html', 'br'):
        token_before_head(p, tok)


def token_before_head(p, tok):
    p.insert_fake('head')
    p.head_element = p.current
    p.mode = IN_HEAD
    p.process_token(tok)


def start_tag_in_head(p, tok):
    t = tok.tid
    if t == 'html':
        start_tag_in_body(p, tok)
    elif t in ('base', 'basefont', 'bgsound', 'link', 'meta'):
        p.append_element(tok, NS_HTML)
    elif t == 'title':
        p.switch_to_text(tok, 'rcdata')
    elif t == 'noscript':
        p.switch_to_text(tok, 'rawtext')  # scripting is enabled in cheerio
    elif t in ('noframes', 'style'):
        p.switch_to_text(tok, 'rawtext')
    elif t == 'script':
        p.switch_to_text(tok, 'script')
    elif t == 'template':
        p.insert_template(tok)
        p.afe.insert(0, _MARKER)
        p.frameset_ok = False
        p.mode = IN_TEMPLATE
        p.tmpl_modes.insert(0, IN_TEMPLATE)
    elif t == 'head':
        pass
    else:
        token_in_head(p, tok)


def end_tag_in_head(p, tok):
    t = tok.tid
    if t == 'head':
        p.pop()
        p.mode = AFTER_HEAD
    elif t in ('body', 'br', 'html'):
        token_in_head(p, tok)
    elif t == 'template':
        template_end_tag_in_head(p, tok)


def template_end_tag_in_head(p, tok):
    if p.tmpl_count > 0:
        p.generate_implied_end_tags_thoroughly()
        p.pop_until_tag_popped('template')
        p.afe_clear_to_last_marker()
        p.tmpl_modes.pop(0)
        p.reset_insertion_mode()


def token_in_head(p, tok):
    p.pop()
    p.mode = AFTER_HEAD
    p.process_token(tok)


def token_in_head_no_script(p, tok):
    p.pop()
    p.mode = IN_HEAD
    p.process_token(tok)


def start_tag_after_head(p, tok):
    t = tok.tid
    if t == 'html':
        start_tag_in_body(p, tok)
    elif t == 'body':
        p.insert_element(tok, NS_HTML)
        p.frameset_ok = False
        p.mode = IN_BODY
    elif t == 'frameset':
        p.insert_element(tok, NS_HTML)
        p.mode = IN_FRAMESET
    elif t in ('base', 'basefont', 'bgsound', 'link', 'meta', 'noframes', 'script', 'style', 'template', 'title'):
        p.push(p.head_element)
        start_tag_in_head(p, tok)
        p.remove_from_stack(p.head_element)
    elif t == 'head':
        pass
    else:
        token_after_head(p, tok)


def end_tag_after_head(p, tok):
    t = tok.tid
    if t in ('body', 'html', 'br'):
        token_after_head(p, tok)
    elif t == 'template':
        template_end_tag_in_head(p, tok)


def token_after_head(p, tok):
    p.insert_fake('body')
    p.mode = IN_BODY
    mode_in_body(p, tok)


def mode_in_body(p, tok):
    t = tok.type
    if t == 'char':
        character_in_body(p, tok)
    elif t == 'ws':
        whitespace_in_body(p, tok)
    elif t == 'comment':
        p.append_comment(tok, p._cur_tmpl_content_or_node())
    elif t == 'start':
        start_tag_in_body(p, tok)
    elif t == 'end':
        end_tag_in_body(p, tok)
    elif t == 'eof':
        eof_in_body(p, tok)


def whitespace_in_body(p, tok):
    p.reconstruct_afe()
    p.insert_characters(tok)


def character_in_body(p, tok):
    p.reconstruct_afe()
    p.insert_characters(tok)
    p.frameset_ok = False


def start_tag_in_body(p, tok):
    t = tok.tid
    if t in FORMATTING_B:
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
        p.afe_push(p.current, tok)
    elif t == 'a':
        entry = p.afe_find_in_scope('a')
        if entry is not None:
            call_adoption_agency(p, tok)
            p.remove_from_stack(entry.element)
            p.afe_remove(entry)
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
        p.afe_push(p.current, tok)
    elif t in NUMBERED_HEADERS:
        if p.has_in_button_scope('p'):
            p.close_p()
        if p.current_tid in NUMBERED_HEADERS:
            p.pop()
        p.insert_element(tok, NS_HTML)
    elif t in ADDRESS_LIKE:
        if p.has_in_button_scope('p'):
            p.close_p()
        p.insert_element(tok, NS_HTML)
    elif t in ('li', 'dd', 'dt'):
        list_item_start(p, tok)
    elif t in ('br', 'img', 'wbr', 'area', 'embed', 'keygen'):
        p.reconstruct_afe()
        p.append_element(tok, NS_HTML)
        p.frameset_ok = False
    elif t == 'hr':
        if p.has_in_button_scope('p'):
            p.close_p()
        p.append_element(tok, NS_HTML)
        p.frameset_ok = False
    elif t in ('rb', 'rtc'):
        if p.has_in_scope('ruby'):
            p.generate_implied_end_tags()
        p.insert_element(tok, NS_HTML)
    elif t in ('rt', 'rp'):
        if p.has_in_scope('ruby'):
            p.generate_implied_end_tags_with_exclusion('rtc')
        p.insert_element(tok, NS_HTML)
    elif t in ('pre', 'listing'):
        if p.has_in_button_scope('p'):
            p.close_p()
        p.insert_element(tok, NS_HTML)
        p.skip_nl = True
        p.frameset_ok = False
    elif t == 'xmp':
        if p.has_in_button_scope('p'):
            p.close_p()
        p.reconstruct_afe()
        p.frameset_ok = False
        p.switch_to_text(tok, 'rawtext')
    elif t == 'svg':
        p.reconstruct_afe()
        adjust_svg_attrs(tok)
        adjust_xml_attrs(tok)
        if tok.self_closing:
            p.append_element(tok, NS_SVG)
        else:
            p.insert_element(tok, NS_SVG)
    elif t == 'html':
        if p.tmpl_count == 0:
            p.adopt_attributes(p.stack[0], tok.attrs)
    elif t in ('base', 'link', 'meta', 'style', 'title', 'script', 'bgsound', 'basefont', 'template'):
        start_tag_in_head(p, tok)
    elif t == 'body':
        body = p.try_peek_body()
        if body is not None and p.tmpl_count == 0:
            p.frameset_ok = False
            p.adopt_attributes(body, tok.attrs)
    elif t == 'form':
        in_template = p.tmpl_count > 0
        if p.form_element is None or in_template:
            if p.has_in_button_scope('p'):
                p.close_p()
            p.insert_element(tok, NS_HTML)
            if not in_template:
                p.form_element = p.current
    elif t == 'nobr':
        p.reconstruct_afe()
        if p.has_in_scope('nobr'):
            call_adoption_agency(p, tok)
            p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
        p.afe_push(p.current, tok)
    elif t == 'math':
        p.reconstruct_afe()
        adjust_mathml_attrs(tok)
        adjust_xml_attrs(tok)
        if tok.self_closing:
            p.append_element(tok, NS_MATHML)
        else:
            p.insert_element(tok, NS_MATHML)
    elif t == 'table':
        if p.document.doc_mode != 'quirks' and p.has_in_button_scope('p'):
            p.close_p()
        p.insert_element(tok, NS_HTML)
        p.frameset_ok = False
        p.mode = IN_TABLE
    elif t == 'input':
        p.reconstruct_afe()
        p.append_element(tok, NS_HTML)
        if not is_hidden_input(tok):
            p.frameset_ok = False
    elif t in ('param', 'track', 'source'):
        p.append_element(tok, NS_HTML)
    elif t == 'image':
        tok.name = 'img'
        tok.tid = 'img'
        p.reconstruct_afe()
        p.append_element(tok, NS_HTML)
        p.frameset_ok = False
    elif t == 'button':
        if p.has_in_scope('button'):
            p.generate_implied_end_tags()
            p.pop_until_tag_popped('button')
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
        p.frameset_ok = False
    elif t in ('applet', 'object', 'marquee'):
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
        p.afe.insert(0, _MARKER)
        p.frameset_ok = False
    elif t == 'iframe':
        p.frameset_ok = False
        p.switch_to_text(tok, 'rawtext')
    elif t == 'select':
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
        p.frameset_ok = False
        p.mode = IN_SELECT_IN_TABLE if p.mode in (IN_TABLE, IN_CAPTION, IN_TABLE_BODY, IN_ROW, IN_CELL) else IN_SELECT
    elif t in ('option', 'optgroup'):
        if p.current_tid == 'option':
            p.pop()
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)
    elif t in ('noembed', 'noframes'):
        p.switch_to_text(tok, 'rawtext')
    elif t == 'frameset':
        body = p.try_peek_body()
        if p.frameset_ok and body is not None:
            _detach(body)
            p.pop_all_up_to_html()
            p.insert_element(tok, NS_HTML)
            p.mode = IN_FRAMESET
    elif t == 'textarea':
        p.insert_element(tok, NS_HTML)
        p.skip_nl = True
        p.tokenizer.state = 'rcdata'
        p.orig_mode = p.mode
        p.frameset_ok = False
        p.mode = TEXT
    elif t == 'noscript':
        p.switch_to_text(tok, 'rawtext')
    elif t == 'plaintext':
        if p.has_in_button_scope('p'):
            p.close_p()
        p.insert_element(tok, NS_HTML)
        p.tokenizer.state = 'plaintext'
    elif t in ('col', 'th', 'td', 'tr', 'head', 'frame', 'tbody', 'tfoot', 'thead', 'caption', 'colgroup'):
        pass
    else:
        p.reconstruct_afe()
        p.insert_element(tok, NS_HTML)


def is_hidden_input(tok):
    v = get_attr(tok, 'type')
    return v is not None and v.lower() == 'hidden'


def list_item_start(p, tok):
    p.frameset_ok = False
    tn = tok.tid
    for i in range(len(p.stack) - 1, -1, -1):
        el = p.stack[i]
        eid = el.tid
        if (tn == 'li' and eid == 'li') or (tn in ('dd', 'dt') and eid in ('dd', 'dt')):
            p.generate_implied_end_tags_with_exclusion(eid)
            p.pop_until_tag_popped(eid)
            break
        if eid not in ('address', 'div', 'p') and p.is_special(el):
            break
    if p.has_in_button_scope('p'):
        p.close_p()
    p.insert_element(tok, NS_HTML)


def generic_end_tag_in_body(p, tok):
    tn = tok.name
    for i in range(len(p.stack) - 1, 0, -1):
        el = p.stack[i]
        if tok.tid == el.tid:
            p.generate_implied_end_tags_with_exclusion(tok.tid)
            if len(p.stack) - 1 >= i:
                p.shorten_to_length(i)
            break
        if p.is_special(el):
            break


def end_tag_in_body(p, tok):
    t = tok.tid
    if t in FORMATTING_B or t in ('a', 'nobr'):
        call_adoption_agency(p, tok)
    elif t == 'p':
        if not p.has_in_button_scope('p'):
            p.insert_fake('p')
        p.close_p()
    elif t in ADDRESS_END:
        if p.has_in_scope(t):
            p.generate_implied_end_tags()
            p.pop_until_tag_popped(t)
    elif t == 'li':
        if p.has_in_list_item_scope('li'):
            p.generate_implied_end_tags_with_exclusion('li')
            p.pop_until_tag_popped('li')
    elif t in ('dd', 'dt'):
        if p.has_in_scope(t):
            p.generate_implied_end_tags_with_exclusion(t)
            p.pop_until_tag_popped(t)
    elif t in NUMBERED_HEADERS:
        if p.has_numbered_header_in_scope():
            p.generate_implied_end_tags()
            p.pop_until_popped(NUMBERED_HEADERS, NS_HTML)
    elif t == 'br':
        p.reconstruct_afe()
        p.insert_fake('br')
        p.pop()
        p.frameset_ok = False
    elif t == 'body':
        if p.has_in_scope('body'):
            p.mode = AFTER_BODY
            body = p.try_peek_body()
            if body is not None:
                p._set_end_location(body, tok)
    elif t == 'html':
        if p.has_in_scope('body'):
            p.mode = AFTER_BODY
            end_tag_after_body(p, tok)
    elif t == 'form':
        in_template = p.tmpl_count > 0
        form = p.form_element
        if not in_template:
            p.form_element = None
        if (form is not None or in_template) and p.has_in_scope('form'):
            p.generate_implied_end_tags()
            if in_template:
                p.pop_until_tag_popped('form')
            elif form is not None:
                p.remove_from_stack(form)
    elif t in ('applet', 'object', 'marquee'):
        if p.has_in_scope(t):
            p.generate_implied_end_tags()
            p.pop_until_tag_popped(t)
            p.afe_clear_to_last_marker()
    elif t == 'template':
        template_end_tag_in_head(p, tok)
    else:
        generic_end_tag_in_body(p, tok)


def eof_in_body(p, tok):
    if p.tmpl_modes:
        eof_in_template(p, tok)
    else:
        stop_parsing(p, tok)


def end_tag_in_text(p, tok):
    p.pop()
    p.mode = p.orig_mode


def eof_in_text(p, tok):
    p.pop()
    p.mode = p.orig_mode
    p.on_eof(tok)


# ---- tables

def character_in_table(p, tok):
    if p.current_tid in TABLE_STRUCTURE:
        p.pending_chars = []
        p.has_nonws_pending = False
        p.orig_mode = p.mode
        p.mode = IN_TABLE_TEXT
        p.pending_chars.append(tok)
        if tok.type == 'char':
            p.has_nonws_pending = True
    else:
        token_in_table(p, tok)


def token_in_table(p, tok):
    saved = p.foster
    p.foster = True
    mode_in_body(p, tok)
    p.foster = saved


def token_in_table_text(p, tok):
    if p.has_nonws_pending:
        for t in p.pending_chars:
            token_in_table(p, t)
    else:
        for t in p.pending_chars:
            p.insert_characters(t)
    p.mode = p.orig_mode
    p.process_token(tok)


def start_tag_in_table(p, tok):
    t = tok.tid
    if t in ('td', 'th', 'tr'):
        p.clear_back_to(TABLE_CONTEXT)
        p.insert_fake('tbody')
        p.mode = IN_TABLE_BODY
        start_tag_in_table_body(p, tok)
    elif t in ('style', 'script', 'template'):
        start_tag_in_head(p, tok)
    elif t == 'col':
        p.clear_back_to(TABLE_CONTEXT)
        p.insert_fake('colgroup')
        p.mode = IN_COLUMN_GROUP
        start_tag_in_column_group(p, tok)
    elif t == 'form':
        if p.form_element is None and p.tmpl_count == 0:
            p.insert_element(tok, NS_HTML)
            p.form_element = p.current
            p.pop()
    elif t == 'table':
        if p.has_in_table_scope('table'):
            p.pop_until_tag_popped('table')
            p.reset_insertion_mode()
            p.process_start_tag(tok)
    elif t in ('tbody', 'tfoot', 'thead'):
        p.clear_back_to(TABLE_CONTEXT)
        p.insert_element(tok, NS_HTML)
        p.mode = IN_TABLE_BODY
    elif t == 'input':
        if is_hidden_input(tok):
            p.append_element(tok, NS_HTML)
        else:
            token_in_table(p, tok)
    elif t == 'caption':
        p.clear_back_to(TABLE_CONTEXT)
        p.afe.insert(0, _MARKER)
        p.insert_element(tok, NS_HTML)
        p.mode = IN_CAPTION
    elif t == 'colgroup':
        p.clear_back_to(TABLE_CONTEXT)
        p.insert_element(tok, NS_HTML)
        p.mode = IN_COLUMN_GROUP
    else:
        token_in_table(p, tok)


def end_tag_in_table(p, tok):
    t = tok.tid
    if t == 'table':
        if p.has_in_table_scope('table'):
            p.pop_until_tag_popped('table')
            p.reset_insertion_mode()
    elif t == 'template':
        template_end_tag_in_head(p, tok)
    elif t in ('body', 'caption', 'col', 'colgroup', 'html', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr'):
        pass
    else:
        token_in_table(p, tok)


def start_tag_in_caption(p, tok):
    if tok.tid in TABLE_VOID:
        if p.has_in_table_scope('caption'):
            p.generate_implied_end_tags()
            p.pop_until_tag_popped('caption')
            p.afe_clear_to_last_marker()
            p.mode = IN_TABLE
            start_tag_in_table(p, tok)
    else:
        start_tag_in_body(p, tok)


def end_tag_in_caption(p, tok):
    t = tok.tid
    if t in ('caption', 'table'):
        if p.has_in_table_scope('caption'):
            p.generate_implied_end_tags()
            p.pop_until_tag_popped('caption')
            p.afe_clear_to_last_marker()
            p.mode = IN_TABLE
            if t == 'table':
                end_tag_in_table(p, tok)
    elif t in ('body', 'col', 'colgroup', 'html', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr'):
        pass
    else:
        end_tag_in_body(p, tok)


def start_tag_in_column_group(p, tok):
    t = tok.tid
    if t == 'html':
        start_tag_in_body(p, tok)
    elif t == 'col':
        p.append_element(tok, NS_HTML)
    elif t == 'template':
        start_tag_in_head(p, tok)
    else:
        token_in_column_group(p, tok)


def end_tag_in_column_group(p, tok):
    t = tok.tid
    if t == 'colgroup':
        if p.current_tid == 'colgroup':
            p.pop()
            p.mode = IN_TABLE
    elif t == 'template':
        template_end_tag_in_head(p, tok)
    elif t == 'col':
        pass
    else:
        token_in_column_group(p, tok)


def token_in_column_group(p, tok):
    if p.current_tid == 'colgroup':
        p.pop()
        p.mode = IN_TABLE
        p.process_token(tok)


def start_tag_in_table_body(p, tok):
    t = tok.tid
    if t == 'tr':
        p.clear_back_to(TABLE_BODY_CONTEXT)
        p.insert_element(tok, NS_HTML)
        p.mode = IN_ROW
    elif t in ('th', 'td'):
        p.clear_back_to(TABLE_BODY_CONTEXT)
        p.insert_fake('tr')
        p.mode = IN_ROW
        start_tag_in_row(p, tok)
    elif t in ('caption', 'col', 'colgroup', 'tbody', 'tfoot', 'thead'):
        if p.has_table_body_context_in_table_scope():
            p.clear_back_to(TABLE_BODY_CONTEXT)
            p.pop()
            p.mode = IN_TABLE
            start_tag_in_table(p, tok)
    else:
        start_tag_in_table(p, tok)


def end_tag_in_table_body(p, tok):
    t = tok.tid
    if t in ('tbody', 'tfoot', 'thead'):
        if p.has_in_table_scope(t):
            p.clear_back_to(TABLE_BODY_CONTEXT)
            p.pop()
            p.mode = IN_TABLE
    elif t == 'table':
        if p.has_table_body_context_in_table_scope():
            p.clear_back_to(TABLE_BODY_CONTEXT)
            p.pop()
            p.mode = IN_TABLE
            end_tag_in_table(p, tok)
    elif t in ('body', 'caption', 'col', 'colgroup', 'html', 'td', 'th', 'tr'):
        pass
    else:
        end_tag_in_table(p, tok)


def start_tag_in_row(p, tok):
    t = tok.tid
    if t in ('th', 'td'):
        p.clear_back_to(TABLE_ROW_CONTEXT)
        p.insert_element(tok, NS_HTML)
        p.mode = IN_CELL
        p.afe.insert(0, _MARKER)
    elif t in ('caption', 'col', 'colgroup', 'tbody', 'tfoot', 'thead', 'tr'):
        if p.has_in_table_scope('tr'):
            p.clear_back_to(TABLE_ROW_CONTEXT)
            p.pop()
            p.mode = IN_TABLE_BODY
            start_tag_in_table_body(p, tok)
    else:
        start_tag_in_table(p, tok)


def end_tag_in_row(p, tok):
    t = tok.tid
    if t == 'tr':
        if p.has_in_table_scope('tr'):
            p.clear_back_to(TABLE_ROW_CONTEXT)
            p.pop()
            p.mode = IN_TABLE_BODY
    elif t == 'table':
        if p.has_in_table_scope('tr'):
            p.clear_back_to(TABLE_ROW_CONTEXT)
            p.pop()
            p.mode = IN_TABLE_BODY
            end_tag_in_table_body(p, tok)
    elif t in ('tbody', 'tfoot', 'thead'):
        if p.has_in_table_scope(t) or p.has_in_table_scope('tr'):
            p.clear_back_to(TABLE_ROW_CONTEXT)
            p.pop()
            p.mode = IN_TABLE_BODY
            end_tag_in_table_body(p, tok)
    elif t in ('body', 'caption', 'col', 'colgroup', 'html', 'td', 'th'):
        pass
    else:
        end_tag_in_table(p, tok)


def start_tag_in_cell(p, tok):
    if tok.tid in TABLE_VOID:
        if p.has_in_table_scope('td') or p.has_in_table_scope('th'):
            p.close_table_cell()
            start_tag_in_row(p, tok)
    else:
        start_tag_in_body(p, tok)


def end_tag_in_cell(p, tok):
    t = tok.tid
    if t in ('td', 'th'):
        if p.has_in_table_scope(t):
            p.generate_implied_end_tags()
            p.pop_until_tag_popped(t)
            p.afe_clear_to_last_marker()
            p.mode = IN_ROW
    elif t in ('table', 'tbody', 'tfoot', 'thead', 'tr'):
        if p.has_in_table_scope(t):
            p.close_table_cell()
            end_tag_in_row(p, tok)
    elif t in ('body', 'caption', 'col', 'colgroup', 'html'):
        pass
    else:
        end_tag_in_body(p, tok)


# ---- select

def start_tag_in_select(p, tok):
    t = tok.tid
    if t == 'html':
        start_tag_in_body(p, tok)
    elif t == 'option':
        if p.current_tid == 'option':
            p.pop()
        p.insert_element(tok, NS_HTML)
    elif t == 'optgroup':
        if p.current_tid == 'option':
            p.pop()
        if p.current_tid == 'optgroup':
            p.pop()
        p.insert_element(tok, NS_HTML)
    elif t == 'hr':
        if p.current_tid == 'option':
            p.pop()
        if p.current_tid == 'optgroup':
            p.pop()
        p.append_element(tok, NS_HTML)
    elif t in ('input', 'keygen', 'textarea', 'select'):
        if p.has_in_select_scope('select'):
            p.pop_until_tag_popped('select')
            p.reset_insertion_mode()
            if t != 'select':
                p.process_start_tag(tok)
    elif t in ('script', 'template'):
        start_tag_in_head(p, tok)


def end_tag_in_select(p, tok):
    t = tok.tid
    if t == 'optgroup':
        if len(p.stack) > 1 and p.current_tid == 'option' and p.stack[-2].tid == 'optgroup':
            p.pop()
        if p.current_tid == 'optgroup':
            p.pop()
    elif t == 'option':
        if p.current_tid == 'option':
            p.pop()
    elif t == 'select':
        if p.has_in_select_scope('select'):
            p.pop_until_tag_popped('select')
            p.reset_insertion_mode()
    elif t == 'template':
        template_end_tag_in_head(p, tok)


_SEL_TABLE = frozenset(['caption', 'table', 'tbody', 'tfoot', 'thead', 'tr', 'td', 'th'])


def start_tag_in_select_in_table(p, tok):
    if tok.tid in _SEL_TABLE:
        p.pop_until_tag_popped('select')
        p.reset_insertion_mode()
        p.process_start_tag(tok)
    else:
        start_tag_in_select(p, tok)


def end_tag_in_select_in_table(p, tok):
    if tok.tid in _SEL_TABLE:
        if p.has_in_table_scope(tok.tid):
            p.pop_until_tag_popped('select')
            p.reset_insertion_mode()
            p.on_end_tag(tok)
    else:
        end_tag_in_select(p, tok)


# ---- template

def start_tag_in_template(p, tok):
    t = tok.tid
    if t in ('base', 'basefont', 'bgsound', 'link', 'meta', 'noframes', 'script', 'style', 'template', 'title'):
        start_tag_in_head(p, tok)
    elif t in ('caption', 'colgroup', 'tbody', 'tfoot', 'thead'):
        p.tmpl_modes[0] = IN_TABLE
        p.mode = IN_TABLE
        start_tag_in_table(p, tok)
    elif t == 'col':
        p.tmpl_modes[0] = IN_COLUMN_GROUP
        p.mode = IN_COLUMN_GROUP
        start_tag_in_column_group(p, tok)
    elif t == 'tr':
        p.tmpl_modes[0] = IN_TABLE_BODY
        p.mode = IN_TABLE_BODY
        start_tag_in_table_body(p, tok)
    elif t in ('td', 'th'):
        p.tmpl_modes[0] = IN_ROW
        p.mode = IN_ROW
        start_tag_in_row(p, tok)
    else:
        p.tmpl_modes[0] = IN_BODY
        p.mode = IN_BODY
        start_tag_in_body(p, tok)


def end_tag_in_template(p, tok):
    if tok.tid == 'template':
        template_end_tag_in_head(p, tok)


def eof_in_template(p, tok):
    if p.tmpl_count > 0:
        p.pop_until_tag_popped('template')
        p.afe_clear_to_last_marker()
        p.tmpl_modes.pop(0)
        p.reset_insertion_mode()
        p.on_eof(tok)
    else:
        stop_parsing(p, tok)


# ---- after body / frameset

def start_tag_after_body(p, tok):
    if tok.tid == 'html':
        start_tag_in_body(p, tok)
    else:
        token_after_body(p, tok)


def end_tag_after_body(p, tok):
    if tok.tid == 'html':
        p.mode = AFTER_AFTER_BODY
        if p.stack and p.stack[0].tid == 'html':
            p._set_end_location(p.stack[0], tok)
            if len(p.stack) > 1:
                body = p.stack[1]
                if not body.end_tag:
                    p._set_end_location(body, tok)
    else:
        token_after_body(p, tok)


def token_after_body(p, tok):
    p.mode = IN_BODY
    mode_in_body(p, tok)


def start_tag_in_frameset(p, tok):
    t = tok.tid
    if t == 'html':
        start_tag_in_body(p, tok)
    elif t == 'frameset':
        p.insert_element(tok, NS_HTML)
    elif t == 'frame':
        p.append_element(tok, NS_HTML)
    elif t == 'noframes':
        start_tag_in_head(p, tok)


def end_tag_in_frameset(p, tok):
    if tok.tid == 'frameset' and not (len(p.stack) == 1 and p.stack[0].tid == 'html'):
        p.pop()
        if p.current_tid != 'frameset':
            p.mode = AFTER_FRAMESET


def start_tag_after_frameset(p, tok):
    if tok.tid == 'html':
        start_tag_in_body(p, tok)
    elif tok.tid == 'noframes':
        start_tag_in_head(p, tok)


def end_tag_after_frameset(p, tok):
    if tok.tid == 'html':
        p.mode = AFTER_AFTER_FRAMESET


def start_tag_after_after_body(p, tok):
    if tok.tid == 'html':
        start_tag_in_body(p, tok)
    else:
        token_after_after_body(p, tok)


def token_after_after_body(p, tok):
    p.mode = IN_BODY
    mode_in_body(p, tok)


def start_tag_after_after_frameset(p, tok):
    if tok.tid == 'html':
        start_tag_in_body(p, tok)
    elif tok.tid == 'noframes':
        start_tag_in_head(p, tok)


def _initial_tag(p, tok):
    token_in_initial(p, tok)


def _in_table_text_tag(p, tok):
    token_in_table_text(p, tok)


def _text_end(p, tok):
    end_tag_in_text(p, tok)


START_TAG_MODES = {
    INITIAL: _initial_tag,
    BEFORE_HTML: start_tag_before_html,
    BEFORE_HEAD: start_tag_before_head,
    IN_HEAD: start_tag_in_head,
    AFTER_HEAD: start_tag_after_head,
    IN_BODY: start_tag_in_body,
    IN_TABLE: start_tag_in_table,
    IN_TABLE_TEXT: _in_table_text_tag,
    IN_CAPTION: start_tag_in_caption,
    IN_COLUMN_GROUP: start_tag_in_column_group,
    IN_TABLE_BODY: start_tag_in_table_body,
    IN_ROW: start_tag_in_row,
    IN_CELL: start_tag_in_cell,
    IN_SELECT: start_tag_in_select,
    IN_SELECT_IN_TABLE: start_tag_in_select_in_table,
    IN_TEMPLATE: start_tag_in_template,
    AFTER_BODY: start_tag_after_body,
    IN_FRAMESET: start_tag_in_frameset,
    AFTER_FRAMESET: start_tag_after_frameset,
    AFTER_AFTER_BODY: start_tag_after_after_body,
    AFTER_AFTER_FRAMESET: start_tag_after_after_frameset,
}

END_TAG_MODES = {
    INITIAL: _initial_tag,
    BEFORE_HTML: end_tag_before_html,
    BEFORE_HEAD: end_tag_before_head,
    IN_HEAD: end_tag_in_head,
    AFTER_HEAD: end_tag_after_head,
    IN_BODY: end_tag_in_body,
    TEXT: _text_end,
    IN_TABLE: end_tag_in_table,
    IN_TABLE_TEXT: _in_table_text_tag,
    IN_CAPTION: end_tag_in_caption,
    IN_COLUMN_GROUP: end_tag_in_column_group,
    IN_TABLE_BODY: end_tag_in_table_body,
    IN_ROW: end_tag_in_row,
    IN_CELL: end_tag_in_cell,
    IN_SELECT: end_tag_in_select,
    IN_SELECT_IN_TABLE: end_tag_in_select_in_table,
    IN_TEMPLATE: end_tag_in_template,
    AFTER_BODY: end_tag_after_body,
    IN_FRAMESET: end_tag_in_frameset,
    AFTER_FRAMESET: end_tag_after_frameset,
    AFTER_AFTER_BODY: token_after_after_body,
}


# --------------------------------------------------------------------------- foreign content

def adjust_svg_attrs(tok):
    for a in tok.attrs:
        adj = SVG_ATTRS.get(a[0])
        if adj is not None:
            a[0] = adj


def adjust_mathml_attrs(tok):
    for a in tok.attrs:
        if a[0] == 'definitionurl':
            a[0] = 'definitionURL'
            break


def adjust_xml_attrs(tok):
    # names such as xlink:href keep their text; only the (unused) namespace bookkeeping is skipped
    pass


def causes_exit(tok):
    t = tok.tid
    if t == 'font' and any(a[0] in ('color', 'size', 'face') for a in tok.attrs):
        return True
    return t in EXITS_FOREIGN


def pop_until_html_or_integration_point(p):
    while p.stack and p.stack[-1].ns != NS_HTML and not p._is_integration_point(p.stack[-1].tid, p.stack[-1]):
        p.pop()


def start_tag_in_foreign(p, tok):
    if causes_exit(tok):
        pop_until_html_or_integration_point(p)
        p.start_tag_outside_foreign(tok)
    else:
        cur = p.current
        ns = cur.ns
        if ns == NS_MATHML:
            adjust_mathml_attrs(tok)
        elif ns == NS_SVG:
            adj = SVG_TAGS.get(tok.name)
            if adj is not None:
                tok.name = adj
                tok.tid = adj
            adjust_svg_attrs(tok)
        if tok.self_closing:
            p.append_element(tok, ns)
        else:
            p.insert_element(tok, ns)


def end_tag_in_foreign(p, tok):
    if tok.tid in ('p', 'br'):
        pop_until_html_or_integration_point(p)
        p.end_tag_outside_foreign(tok)
        return
    for i in range(len(p.stack) - 1, 0, -1):
        el = p.stack[i]
        if el.ns == NS_HTML:
            p.end_tag_outside_foreign(tok)
            break
        if el.name.lower() == tok.name:
            tok.name = el.name  # for the end location check
            p.shorten_to_length(i)
            break


# --------------------------------------------------------------------------- public API

def parse_document(html_text):
    """Parse an HTML document string and return the root Fragment (children: doctype-less tree)."""
    text = html_text.replace('\r\n', '\n').replace('\r', '\n')
    p = Parser()
    tok = Tokenizer(text, p)
    p.run(tok)
    return p.document


def walk_elements(node):
    """Generator of Elements below `node` in document order."""
    stack = [iter(getattr(node, 'children', []))]
    while stack:
        try:
            c = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(c, Element):
            yield c
        kids = getattr(c, 'children', None)
        if kids:
            stack.append(iter(kids))


def text_content(node):
    """domutils.textContent: concatenated text of all descendants (comments excluded)."""
    if isinstance(node, Text):
        return node.data
    out = []
    stack = [iter(getattr(node, 'children', []))]
    while stack:
        try:
            c = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(c, Text):
            out.append(c.data)
        else:
            kids = getattr(c, 'children', None)
            if kids:
                stack.append(iter(kids))
    return ''.join(out)


_VOID = frozenset('area base basefont bgsound br col embed frame hr img input keygen link meta param source track wbr'.split())
_RAW = frozenset('style script xmp iframe noembed noframes plaintext noscript'.split())


def serialize_outer(el):
    """Rough equivalent of parse5's serializeOuter (enough to run text searches on a form's markup)."""
    out = []

    def rec(n):
        if isinstance(n, Text):
            out.append(n.data if (n.parent is not None and getattr(n.parent, 'tid', None) in _RAW) else n.data)
        elif isinstance(n, Comment):
            out.append('<!--' + n.data + '-->')
        elif isinstance(n, Fragment):
            for c in n.children:
                rec(c)
        elif isinstance(n, Element):
            out.append('<' + n.name)
            for k, v in n.attrs.items():
                out.append(' ' + k + '="' + v.replace('&', '&amp;').replace('"', '&quot;') + '"')
            out.append('>')
            if n.tid in _VOID and n.ns == NS_HTML:
                return
            for c in n.children:
                rec(c)
            out.append('</' + n.name + '>')

    rec(el)
    return ''.join(out)
