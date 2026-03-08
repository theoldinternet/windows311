from flask import Flask, render_template, jsonify, request, session, abort
import datetime
import os
import shutil
import fnmatch
import stat
import sqlite3
from basic_interp import BASICInterpreter, InputNeeded, BASICError

app = Flask(__name__)
app.secret_key = 'qbasic-windows311'

# ── Honeypot DB ───────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'honeypot.db')

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    with _db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS dos_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                ip        TEXT    NOT NULL,
                command   TEXT    NOT NULL,
                cwd       TEXT    NOT NULL,
                output    TEXT
            );
            CREATE TABLE IF NOT EXISTS notepad_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                ip        TEXT    NOT NULL,
                path      TEXT    NOT NULL,
                content   TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS qbasic_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                ip        TEXT    NOT NULL,
                event     TEXT    NOT NULL,
                filename  TEXT,
                code      TEXT    NOT NULL,
                output    TEXT
            );
            CREATE TABLE IF NOT EXISTS ip_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT    NOT NULL,
                first_seen TEXT    NOT NULL,
                last_seen  TEXT    NOT NULL,
                hits       INTEGER NOT NULL DEFAULT 1,
                user_agent TEXT,
                UNIQUE(ip)
            );
        ''')

_init_db()

def _client_ip() -> str:
    """Return the real client IP, respecting X-Forwarded-For from nginx."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

def _log_ip():
    ip = _client_ip()
    ua = request.headers.get('User-Agent', '')
    now = datetime.datetime.utcnow().isoformat()
    with _db() as conn:
        conn.execute('''
            INSERT INTO ip_log (ip, first_seen, last_seen, hits, user_agent)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen  = excluded.last_seen,
                hits       = hits + 1,
                user_agent = excluded.user_agent
        ''', (ip, now, now, ua))

def _check_ip_session():
    """Abort if the session belongs to a different IP than the current request."""
    ip = _client_ip()
    _log_ip()
    if 'ip' not in session:
        session['ip'] = ip
    elif session['ip'] != ip:
        abort(403)

# ── QBasic interpreter pool (one per "session" — keyed by session token) ──────
_interp_pool: dict[str, BASICInterpreter] = {}

def _get_interp(sid: str) -> BASICInterpreter:
    if sid not in _interp_pool:
        _interp_pool[sid] = BASICInterpreter()
    return _interp_pool[sid]

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DOS_ROOT  = os.path.join(BASE_DIR, 'dos_root')

def _seed_dos_root():
    """Create a starter virtual C: drive."""
    dirs = ['DOS', 'WINDOWS', 'DOCS', 'GAMES', 'TEMP']
    for d in dirs:
        os.makedirs(os.path.join(DOS_ROOT, d), exist_ok=True)

    files = {
        'AUTOEXEC.BAT': '@ECHO OFF\nPROMPT $P$G\nPATH C:\\DOS;C:\\WINDOWS\nSET TEMP=C:\\TEMP\n',
        'CONFIG.SYS':   'FILES=30\nBUFFERS=20\nDEVICE=C:\\DOS\\HIMEM.SYS\n',
        'README.TXT':   'Welcome to MS-DOS 6.22\r\nType HELP for a list of commands.\r\n',
        'DOS\\COMMAND.COM': '',
        'WINDOWS\\WIN.INI': '[windows]\nload=\nrun=\n',
        'DOCS\\README.TXT': 'This is your documents folder.\r\n',
        'GAMES\\README.TXT': 'No games installed.\r\nTry typing HELP.\r\n',
    }
    for rel, content in files.items():
        path = os.path.join(DOS_ROOT, rel.replace('\\', os.sep))
        if not os.path.exists(path):
            with open(path, 'w') as f:
                f.write(content)

_seed_dos_root()

# ── Path helpers ─────────────────────────────────────────────────────────────

def _dos_cwd_to_real(dos_cwd: str) -> str:
    rel = dos_cwd.upper().lstrip('C:').lstrip('\\').lstrip('/')
    return os.path.normpath(os.path.join(DOS_ROOT, rel.replace('\\', os.sep))) if rel else DOS_ROOT

def _resolve(dos_cwd: str, dos_path: str):
    """Resolve a DOS path argument to a real path, sandboxed to DOS_ROOT."""
    p = dos_path.strip('"\'').upper()
    if p.startswith('C:\\') or p.startswith('C:/'):
        rel = p[3:].replace('\\', os.sep).replace('/', os.sep)
        real = os.path.normpath(os.path.join(DOS_ROOT, rel))
    elif p.startswith('\\') or p.startswith('/'):
        real = os.path.normpath(os.path.join(DOS_ROOT, p[1:].replace('\\', os.sep)))
    else:
        cwd_real = _dos_cwd_to_real(dos_cwd)
        real = os.path.normpath(os.path.join(cwd_real, p.replace('\\', os.sep)))
    if not real.startswith(DOS_ROOT):
        return None
    return real

def _to_dos_path(real: str) -> str:
    rel = os.path.relpath(real, DOS_ROOT)
    return 'C:\\' if rel == '.' else 'C:\\' + rel.replace(os.sep, '\\').upper()

def _dos_name(real: str) -> str:
    """8.3 uppercase filename."""
    return os.path.basename(real).upper()

# ── DIR formatting ────────────────────────────────────────────────────────────

def _dir_listing(real_dir: str, pattern: str = '*', wide: bool = False) -> str:
    dos_path = _to_dos_path(real_dir)
    header = [
        ' Volume in drive C is MS-DOS_6',
        ' Volume Serial Number is 1992-0311',
        f' Directory of {dos_path}',
        '',
    ]

    names = []
    try:
        for name in sorted(os.listdir(real_dir)):
            if fnmatch.fnmatch(name.upper(), pattern.upper()):
                names.append(name)
    except PermissionError:
        return 'Access denied.'

    if not names:
        return f'File not found - {pattern}'

    file_count  = 0
    dir_count   = 0
    total_bytes = 0

    if wide:
        # 5 columns of 16 chars each
        COL_W   = 16
        PER_ROW = 5
        tokens  = []
        for name in names:
            full = os.path.join(real_dir, name)
            if os.path.isdir(full):
                dir_count += 1
                tokens.append(f'[{name.upper()}]')
            else:
                file_count  += 1
                total_bytes += os.stat(full).st_size
                tokens.append(name.upper())
        body = []
        for i in range(0, len(tokens), PER_ROW):
            row = tokens[i:i + PER_ROW]
            body.append(''.join(t.ljust(COL_W) for t in row).rstrip())
    else:
        body = []
        for name in names:
            full  = os.path.join(real_dir, name)
            st    = os.stat(full)
            mtime = datetime.datetime.fromtimestamp(st.st_mtime)
            date_s = mtime.strftime('%m-%d-%y')
            time_s = mtime.strftime('%I:%M%p').lower()
            if os.path.isdir(full):
                dir_count += 1
                body.append(f'{name.upper():<8}         <DIR>     {date_s}  {time_s}')
            else:
                size = st.st_size
                file_count  += 1
                total_bytes += size
                body.append(f'{name.upper():<12} {size:>9,}  {date_s}  {time_s}')

    free = shutil.disk_usage(DOS_ROOT).free
    footer = [
        f'       {file_count} file(s)      {total_bytes:>10,} bytes',
        f'       {dir_count} dir(s)   {free:>12,} bytes free',
    ]
    return '\r\n'.join(header + body + footer)

# ── Flag / arg parser ─────────────────────────────────────────────────────────

import re as _re

def _parse(args: str):
    """
    Split DOS args into (flags_set, flag_values_dict, positional_list).
    Handles /FLAG, /FLAG:VALUE, and quoted positional args.
    Example: '/S /O:N "MY DIR" FILE.TXT'
      flags  = {'S', 'O'}
      fvals  = {'O': 'N'}
      pos    = ['MY DIR', 'FILE.TXT']
    """
    flags, fvals, pos = set(), {}, []
    for tok in _re.findall(r'/(\w+)(?::(\S*))?|"([^"]+)"|(\S+)', args):
        flag_name, flag_val, quoted, plain = tok
        if flag_name:
            flags.add(flag_name.upper())
            if flag_val:
                fvals[flag_name.upper()] = flag_val.upper()
        elif quoted:
            pos.append(quoted)
        elif plain and not plain.startswith('/'):
            pos.append(plain)
    return flags, fvals, pos


# ── Recursive helpers ──────────────────────────────────────────────────────────

def _xcopy_tree(src_real, dst_real, include_empty=False):
    """Recursively copy src_real → dst_real. Returns list of copied file paths."""
    copied = []
    os.makedirs(dst_real, exist_ok=True)
    for name in os.listdir(src_real):
        s = os.path.join(src_real, name)
        d = os.path.join(dst_real, name)
        if os.path.isdir(s):
            sub = _xcopy_tree(s, d, include_empty)
            copied.extend(sub)
        else:
            shutil.copy2(s, d)
            copied.append(d)
    return copied


def _dir_recursive(real_dir, pattern='*', wide=False):
    """DIR /S — yield listing strings for dir and all subdirs."""
    out = [_dir_listing(real_dir, pattern, wide)]
    for name in sorted(os.listdir(real_dir)):
        full = os.path.join(real_dir, name)
        if os.path.isdir(full):
            sub = _dir_recursive(full, pattern, wide)
            out.extend([''] + sub)
    return out


# ── Command dispatcher ────────────────────────────────────────────────────────

def run_dos_command(raw: str, dos_cwd: str):
    """Execute one DOS command.
    Returns (output_text, new_dos_cwd, clear, exit_shell, meta_dict).
    meta_dict carries optional client-side actions: color, edit, title.
    """
    raw = raw.strip()
    if not raw:
        return ('', dos_cwd, False, False, {})

    # Handle REM immediately (batch comment — produce no output)
    if raw.upper().startswith('REM'):
        return ('', dos_cwd, False, False, {})

    parts = raw.split(None, 1)
    cmd   = parts[0].upper()
    args  = parts[1].strip() if len(parts) > 1 else ''

    cwd_real = _dos_cwd_to_real(dos_cwd)

    def R(out='', cwd=None, clear=False, exit_=False, meta=None):
        return (out, cwd or dos_cwd, clear, exit_, meta or {})

    # ── VER ──────────────────────────────────────────────────────────────────
    if cmd == 'VER':
        return R('MS-DOS Version 6.22')

    # ── CLS ──────────────────────────────────────────────────────────────────
    if cmd == 'CLS':
        return R(clear=True)

    # ── EXIT ─────────────────────────────────────────────────────────────────
    if cmd == 'EXIT':
        return R(exit_=True)

    # ── ECHO ─────────────────────────────────────────────────────────────────
    if cmd == 'ECHO':
        if not args:
            return R('ECHO is on.')
        if args.upper() == 'ON':
            return R()
        if args.upper() == 'OFF':
            return R()
        return R(args)

    # ── PAUSE ────────────────────────────────────────────────────────────────
    if cmd == 'PAUSE':
        return R('Press any key to continue . . .')

    # ── DATE ─────────────────────────────────────────────────────────────────
    if cmd == 'DATE':
        d = datetime.date.today()
        return R(f'Current date is {d.strftime("%a %m-%d-%Y")}')

    # ── TIME ─────────────────────────────────────────────────────────────────
    if cmd == 'TIME':
        t = datetime.datetime.now()
        return R(f'Current time is {t.strftime("%I:%M:%S.%f")[:11]}')

    # ── MEM ──────────────────────────────────────────────────────────────────
    if cmd == 'MEM':
        flags, _, _ = _parse(args)
        if 'C' in flags or 'CLASSIFY' in flags:
            out = (
                'Modules using memory below 1 MB:\n\n'
                '  Name         Total      Conventional  Upper Memory\n'
                '  --------  ----------   ------------  ------------\n'
                '  MSDOS      16,624  (16K)   16,624  (16K)        0  (0K)\n'
                '  HIMEM       1,168   (1K)    1,168   (1K)        0  (0K)\n'
                '  Free      634,912 (620K)  634,912 (620K)        0  (0K)\n'
            )
        else:
            out = (
                'Memory Type        Total    Used    Free\n'
                '--------------  -------- -------- --------\n'
                'Conventional       640K     136K     504K\n'
                'Upper                0K       0K       0K\n'
                'Extended (XMS)  15,360K     256K  15,104K\n'
                '--------------  -------- -------- --------\n'
                'Total memory    16,000K     392K  15,608K\n\n'
                'Total under 1 MB   640K     136K     504K\n\n'
                'Largest executable program size    504K (516,096 bytes)\n'
                'Largest free upper memory block      0K (0 bytes)\n'
                'MS-DOS is resident in the high memory area.'
            )
        return R(out)

    # ── VOL ──────────────────────────────────────────────────────────────────
    if cmd == 'VOL':
        return R(' Volume in drive C is MS-DOS_6\n Volume Serial Number is 1992-0311')

    # ── LABEL ────────────────────────────────────────────────────────────────
    if cmd == 'LABEL':
        new_label = args.strip().upper() or 'MS-DOS_6'
        return R(f'Volume label is now {new_label}.')

    # ── PATH ─────────────────────────────────────────────────────────────────
    if cmd == 'PATH':
        if args:
            return R()
        return R('PATH=C:\\DOS;C:\\WINDOWS')

    # ── SET ──────────────────────────────────────────────────────────────────
    if cmd == 'SET':
        if args and '=' in args:
            return R()   # setting a variable — silently accept
        out = (
            'COMSPEC=C:\\DOS\\COMMAND.COM\n'
            'PATH=C:\\DOS;C:\\WINDOWS\n'
            'PROMPT=$P$G\n'
            'TEMP=C:\\TEMP\n'
            'WINDIR=C:\\WINDOWS'
        )
        return R(out)

    # ── VERIFY ───────────────────────────────────────────────────────────────
    if cmd == 'VERIFY':
        if args.upper() in ('ON', 'OFF'):
            return R(f'VERIFY is {args.upper()}.')
        return R('VERIFY is OFF.')

    # ── BREAK ────────────────────────────────────────────────────────────────
    if cmd == 'BREAK':
        state = args.upper() if args.upper() in ('ON', 'OFF') else ''
        return R(f'BREAK is {"ON" if state == "ON" else "OFF"}.')

    # ── CHCP ─────────────────────────────────────────────────────────────────
    if cmd == 'CHCP':
        cp = args.strip() or '437'
        return R(f'Active code page: {cp}')

    # ── DOSKEY ───────────────────────────────────────────────────────────────
    if cmd == 'DOSKEY':
        return R('DOSKey installed.\nUse UP/DOWN arrows to recall commands.')

    # ── PROMPT ───────────────────────────────────────────────────────────────
    if cmd == 'PROMPT':
        return R()   # accept silently; prompt is always $P$G in this sim

    # ── TITLE ────────────────────────────────────────────────────────────────
    if cmd == 'TITLE':
        return R(meta={'title': args.strip() or 'MS-DOS Prompt'})

    # ── COLOR ────────────────────────────────────────────────────────────────
    if cmd == 'COLOR':
        # COLOR [attr]  — attr is two hex digits: bg fg
        DOS_COLORS = {
            '0': '#000000', '1': '#000080', '2': '#008000', '3': '#008080',
            '4': '#800000', '5': '#800080', '6': '#808000', '7': '#c0c0c0',
            '8': '#808080', '9': '#0000ff', 'A': '#00ff00', 'B': '#00ffff',
            'C': '#ff0000', 'D': '#ff00ff', 'E': '#ffff00', 'F': '#ffffff',
        }
        attr = (args.strip().upper() + '07')[:2]
        bg, fg = attr[0], attr[1]
        if bg == fg:
            return R('Invalid color specification.')
        return R(meta={'color': {
            'bg': DOS_COLORS.get(bg, '#000000'),
            'fg': DOS_COLORS.get(fg, '#c0c0c0'),
        }})

    # ── CD / CHDIR ───────────────────────────────────────────────────────────
    if cmd in ('CD', 'CHDIR'):
        if not args:
            return R(dos_cwd)
        if args == '\\':
            return R(cwd='C:\\')
        # Strip trailing backslash
        nav = args.rstrip('\\') or '\\'
        if nav == '..':
            if dos_cwd == 'C:\\':
                return R()
            new_real = os.path.dirname(cwd_real)
            if not new_real.startswith(DOS_ROOT):
                new_real = DOS_ROOT
            return R(cwd=_to_dos_path(new_real))
        # Handle chained .. e.g. ..\..
        if all(p == '..' for p in nav.replace('/', '\\').split('\\') if p):
            cur = cwd_real
            for p in nav.replace('/', '\\').split('\\'):
                if p == '..':
                    cur = os.path.dirname(cur)
                    if not cur.startswith(DOS_ROOT):
                        cur = DOS_ROOT
            return R(cwd=_to_dos_path(cur))
        target = _resolve(dos_cwd, nav)
        if target is None or not os.path.isdir(target):
            return R('Invalid directory.')
        return R(cwd=_to_dos_path(target))

    # ── DIR ──────────────────────────────────────────────────────────────────
    if cmd == 'DIR':
        flags, fvals, pos = _parse(args)
        wide      = 'W' in flags
        bare      = 'B' in flags
        recursive = 'S' in flags
        lower_out = 'L' in flags
        attr_dirs = 'A' in flags and fvals.get('A', '') == 'D'
        sort_key  = fvals.get('O', 'N')   # N=name, S=size, D=date, E=ext
        reverse   = sort_key.startswith('-')
        sort_key  = sort_key.lstrip('-')

        path_arg = pos[0] if pos else ''

        if path_arg:
            target = _resolve(dos_cwd, path_arg)
            if target is None:
                return R('Invalid path.')
            if os.path.isdir(target):
                src_dir, pattern = target, '*'
            else:
                src_dir = os.path.dirname(target) or cwd_real
                pattern = os.path.basename(path_arg).upper()
        else:
            src_dir, pattern = cwd_real, '*'

        if bare:
            # /B — just filenames, no header/footer
            try:
                names = sorted(
                    [n for n in os.listdir(src_dir) if fnmatch.fnmatch(n.upper(), pattern)],
                    key=lambda n: n.upper()
                )
            except OSError:
                return R('File not found.')
            return R('\n'.join(n.upper() for n in names))

        if recursive:
            sections = _dir_recursive(src_dir, pattern, wide)
            return R('\n\n'.join(sections))

        out = _dir_listing(src_dir, pattern, wide)
        if lower_out:
            out = out.lower()
        return R(out)

    # ── MKDIR / MD ───────────────────────────────────────────────────────────
    if cmd in ('MKDIR', 'MD'):
        if not args:
            return R('Required parameter missing.')
        target = _resolve(dos_cwd, args)
        if target is None:
            return R('Access denied.')
        if os.path.exists(target):
            return R('A subdirectory or file already exists.')
        os.makedirs(target, exist_ok=True)
        return R()

    # ── RMDIR / RD ───────────────────────────────────────────────────────────
    if cmd in ('RMDIR', 'RD'):
        if not args:
            return R('Required parameter missing.')
        flags, _, pos = _parse(args)
        force = 'S' in flags
        quiet = 'Q' in flags
        name  = pos[0] if pos else args.lstrip('/')
        target = _resolve(dos_cwd, name)
        if target is None or target == DOS_ROOT:
            return R('Access denied.')
        if not os.path.isdir(target):
            return R('The system cannot find the path specified.')
        if force:
            shutil.rmtree(target)
        else:
            try:
                os.rmdir(target)
            except OSError:
                return R('The directory is not empty.')
        return R()

    # ── DELTREE ──────────────────────────────────────────────────────────────
    if cmd == 'DELTREE':
        if not args:
            return R('Required parameter missing.')
        flags, _, pos = _parse(args)
        name = pos[0] if pos else args
        target = _resolve(dos_cwd, name)
        if target is None or target == DOS_ROOT:
            return R('Access denied.')
        if not os.path.exists(target):
            return R(f'File not found - {name.upper()}')
        if os.path.isdir(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
        return R(f'Deleting {_to_dos_path(target)}...\nAll files in directory will be deleted!')

    # ── TYPE ─────────────────────────────────────────────────────────────────
    if cmd == 'TYPE':
        if not args:
            return R('Required parameter missing.')
        _, _, pos = _parse(args)
        filenames = pos if pos else [args]
        out_parts = []
        for fname in filenames:
            target = _resolve(dos_cwd, fname)
            if target is None or not os.path.isfile(target):
                out_parts.append(f'File not found - {fname.upper()}')
                continue
            try:
                with open(target, 'r', errors='replace') as f:
                    content = f.read()
                if len(filenames) > 1:
                    out_parts.append(f'\n{fname.upper()}\n' + content)
                else:
                    out_parts.append(content)
            except Exception as e:
                out_parts.append(str(e))
        return R('\n'.join(out_parts))

    # ── MORE ─────────────────────────────────────────────────────────────────
    if cmd == 'MORE':
        if not args:
            return R('Usage: MORE filename')
        target = _resolve(dos_cwd, args)
        if target is None or not os.path.isfile(target):
            return R(f'File not found - {args.upper()}')
        with open(target, 'r', errors='replace') as f:
            lines = f.readlines()
        # Show all — terminal scrolls; append a page-end marker
        out = ''.join(lines).rstrip()
        return R(out + '\n-- More -- (end of file)')

    # ── COPY ─────────────────────────────────────────────────────────────────
    if cmd == 'COPY':
        flags, _, pos = _parse(args)
        verify = 'V' in flags
        if len(pos) < 2:
            return R('Required parameter missing.')
        src_arg, dst_arg = pos[0], pos[1]

        # Wildcard source support
        src_base  = _resolve(dos_cwd, os.path.dirname(src_arg) or '.')
        pattern   = os.path.basename(src_arg).upper()
        dst       = _resolve(dos_cwd, dst_arg)
        if src_base is None or dst is None:
            return R('Access denied.')

        if '*' in pattern or '?' in pattern:
            matched = [n for n in os.listdir(src_base)
                       if fnmatch.fnmatch(n.upper(), pattern)
                       and os.path.isfile(os.path.join(src_base, n))]
            if not matched:
                return R(f'File not found - {src_arg.upper()}')
            dest_dir = dst if os.path.isdir(dst) else os.path.dirname(dst)
            for name in matched:
                shutil.copy2(os.path.join(src_base, name), os.path.join(dest_dir, name))
            v = '  Verified.' if verify else ''
            return R(f'        {len(matched)} file(s) copied.{v}')

        src = _resolve(dos_cwd, src_arg)
        if src is None or not os.path.isfile(src):
            return R(f'File not found - {src_arg.upper()}')
        if os.path.isdir(dst):
            dst = os.path.join(dst, os.path.basename(src))
        shutil.copy2(src, dst)
        v = '  Verified.' if verify else ''
        return R(f'        1 file(s) copied.{v}')

    # ── XCOPY ────────────────────────────────────────────────────────────────
    if cmd == 'XCOPY':
        flags, _, pos = _parse(args)
        if len(pos) < 2:
            return R('Required parameter missing.\nXCOPY source destination [/S] [/E] [/V] [/P] [/Y]')
        src = _resolve(dos_cwd, pos[0])
        dst = _resolve(dos_cwd, pos[1])
        if src is None or dst is None:
            return R('Access denied.')
        if not os.path.exists(src):
            return R(f'File not found - {pos[0].upper()}')
        if os.path.isfile(src):
            os.makedirs(dst if os.path.isdir(dst) else os.path.dirname(dst), exist_ok=True)
            d = os.path.join(dst, os.path.basename(src)) if os.path.isdir(dst) else dst
            shutil.copy2(src, d)
            return R(f'{_to_dos_path(d)}\n        1 File(s) copied')
        if 'S' in flags or 'E' in flags:
            copied = _xcopy_tree(src, dst, include_empty='E' in flags)
            lines = [_to_dos_path(p) for p in copied]
            lines.append(f'        {len(copied)} File(s) copied')
            return R('\n'.join(lines))
        # No /S — only files in top-level dir
        os.makedirs(dst, exist_ok=True)
        count = 0
        lines = []
        for name in os.listdir(src):
            full = os.path.join(src, name)
            if os.path.isfile(full):
                d = os.path.join(dst, name)
                shutil.copy2(full, d)
                lines.append(_to_dos_path(d))
                count += 1
        lines.append(f'        {count} File(s) copied')
        return R('\n'.join(lines))

    # ── MOVE ─────────────────────────────────────────────────────────────────
    if cmd == 'MOVE':
        flags, _, pos = _parse(args)
        if len(pos) < 2:
            return R('Required parameter missing.')
        src = _resolve(dos_cwd, pos[0])
        dst = _resolve(dos_cwd, pos[1])
        if src is None or dst is None:
            return R('Access denied.')
        if not os.path.exists(src):
            return R(f'File not found - {pos[0].upper()}')
        if os.path.isdir(dst):
            dst = os.path.join(dst, os.path.basename(src))
        shutil.move(src, dst)
        return R(f'{pos[0].upper()} => {pos[1].upper()}')

    # ── DEL / ERASE ──────────────────────────────────────────────────────────
    if cmd in ('DEL', 'ERASE'):
        if not args:
            return R('Required parameter missing.')
        flags, _, pos = _parse(args)
        target_arg = pos[0] if pos else args
        target = _resolve(dos_cwd, target_arg)
        if target is None:
            return R('Access denied.')
        src_dir  = os.path.dirname(target) if not os.path.isdir(target) else target
        pattern  = os.path.basename(target).upper() if not os.path.isdir(target) else '*'

        if 'S' in flags:
            # Delete matching files in all subdirs
            deleted = 0
            for root, dirs, files in os.walk(src_dir):
                if not root.startswith(DOS_ROOT):
                    continue
                for f in files:
                    if fnmatch.fnmatch(f.upper(), pattern):
                        os.remove(os.path.join(root, f))
                        deleted += 1
            return R(f'{deleted} file(s) deleted.')

        matched = [f for f in os.listdir(src_dir)
                   if fnmatch.fnmatch(f.upper(), pattern)
                   and os.path.isfile(os.path.join(src_dir, f))]
        if not matched:
            return R(f'File not found - {target_arg.upper()}')
        for name in matched:
            os.remove(os.path.join(src_dir, name))
        return R()

    # ── REN / RENAME ─────────────────────────────────────────────────────────
    if cmd in ('REN', 'RENAME'):
        _, _, pos = _parse(args)
        if len(pos) < 2:
            return R('Required parameter missing.')
        src = _resolve(dos_cwd, pos[0])
        if src is None or not os.path.exists(src):
            return R(f'File not found - {pos[0].upper()}')
        dst = os.path.join(os.path.dirname(src), pos[1].strip())
        if not dst.startswith(DOS_ROOT):
            return R('Access denied.')
        os.rename(src, dst)
        return R()

    # ── ATTRIB ───────────────────────────────────────────────────────────────
    if cmd == 'ATTRIB':
        flags, _, pos = _parse(args)
        target_arg = pos[0] if pos else '.'
        target = _resolve(dos_cwd, target_arg) if target_arg != '.' else cwd_real
        if target is None or not os.path.exists(target):
            return R('File not found.')
        if os.path.isdir(target):
            lines = []
            for name in sorted(os.listdir(target)):
                full = os.path.join(target, name)
                ro = 'R' if not os.access(full, os.W_OK) else ' '
                a  = 'A'
                lines.append(f'  {ro}  {a}         {_to_dos_path(full)}')
            return R('\n'.join(lines) if lines else '(empty directory)')
        ro = 'R' if not os.access(target, os.W_OK) else ' '
        return R(f'  {ro}  A         {_to_dos_path(target)}')

    # ── FIND ─────────────────────────────────────────────────────────────────
    if cmd == 'FIND':
        flags, _, _ = _parse(args)
        invert    = 'V' in flags
        count_only= 'C' in flags
        show_nums = 'N' in flags
        # case sensitivity — /I means insensitive (default is sensitive in real DOS)
        case_sens = 'I' not in flags

        m = _re.match(r'(/\w+\s*)*"([^"]*)"(.*)', args, _re.IGNORECASE)
        if not m:
            return R('Syntax: FIND [/V] [/C] [/N] [/I] "string" filename...')
        needle = m.group(2)
        rest   = m.group(3).strip()
        _, _, fnames = _parse(rest)
        if not fnames:
            return R('Required parameter missing.')

        out_parts = []
        for fname in fnames:
            target = _resolve(dos_cwd, fname)
            if target is None or not os.path.isfile(target):
                out_parts.append(f'File not found - {fname.upper()}')
                continue
            out_parts.append(f'---------- {fname.upper()}')
            with open(target, 'r', errors='replace') as f:
                file_lines = f.readlines()
            matched_count = 0
            for i, line in enumerate(file_lines, 1):
                hay  = line if case_sens else line.lower()
                pin  = needle if case_sens else needle.lower()
                hit  = pin in hay
                if invert:
                    hit = not hit
                if hit:
                    matched_count += 1
                    if not count_only:
                        prefix = f'[{i}] ' if show_nums else ''
                        out_parts.append(prefix + line.rstrip())
            if count_only:
                out_parts.append(f'---------- {fname.upper()}: {matched_count}')
        return R('\n'.join(out_parts))

    # ── FC ───────────────────────────────────────────────────────────────────
    if cmd == 'FC':
        flags, _, pos = _parse(args)
        if len(pos) < 2:
            return R('Syntax: FC [/B] [/L] [/N] file1 file2')
        f1 = _resolve(dos_cwd, pos[0])
        f2 = _resolve(dos_cwd, pos[1])
        if f1 is None or not os.path.isfile(f1):
            return R(f'File not found - {pos[0].upper()}')
        if f2 is None or not os.path.isfile(f2):
            return R(f'File not found - {pos[1].upper()}')
        binary = 'B' in flags
        show_n = 'N' in flags
        with open(f1, 'rb' if binary else 'r', errors=None if binary else 'replace') as fh:
            c1 = fh.read()
        with open(f2, 'rb' if binary else 'r', errors=None if binary else 'replace') as fh:
            c2 = fh.read()
        if binary:
            if c1 == c2:
                return R(f'Comparing files {pos[0].upper()} and {pos[1].upper()}\nFC: no differences encountered')
            # Show first differing offset
            for i, (a, b) in enumerate(zip(c1, c2)):
                if a != b:
                    return R(f'Comparing files {pos[0].upper()} and {pos[1].upper()}\n'
                             f'FC: {pos[0].upper()} longer than {pos[1].upper()}'
                             if len(c1) != len(c2) else
                             f'First difference at offset {i:08X}: {a:02X} vs {b:02X}')
        lines1 = c1.splitlines()
        lines2 = c2.splitlines()
        header = f'Comparing files {pos[0].upper()} and {pos[1].upper()}'
        if lines1 == lines2:
            return R(f'{header}\nFC: no differences encountered')
        diffs = [header]
        for i, (l1, l2) in enumerate(zip(lines1, lines2), 1):
            if l1 != l2:
                pfx = f'{i}: ' if show_n else ''
                diffs.append(f'***** {pos[0].upper()}')
                diffs.append(pfx + l1)
                diffs.append(f'***** {pos[1].upper()}')
                diffs.append(pfx + l2)
                diffs.append('*****')
        if len(lines1) != len(lines2):
            diffs.append(f'FC: {pos[0].upper() if len(lines1)>len(lines2) else pos[1].upper()} longer')
        return R('\n'.join(diffs))

    # ── SORT ─────────────────────────────────────────────────────────────────
    if cmd == 'SORT':
        flags, fvals, pos = _parse(args)
        reverse = 'R' in flags
        col     = int(fvals.get('+', fvals.get('', '1')) or 1) - 1
        col     = max(0, col)
        if not pos:
            return R('Usage: SORT [/R] [/+n] filename')
        target = _resolve(dos_cwd, pos[0])
        if target is None or not os.path.isfile(target):
            return R(f'File not found - {pos[0].upper()}')
        with open(target, 'r', errors='replace') as f:
            lines = f.readlines()
        lines.sort(key=lambda l: l[col:].upper(), reverse=reverse)
        return R(''.join(lines).rstrip())

    # ── TREE ─────────────────────────────────────────────────────────────────
    if cmd == 'TREE':
        flags, _, pos = _parse(args)
        show_files = 'F' in flags
        target = _resolve(dos_cwd, pos[0]) if pos else cwd_real
        if target is None or not os.path.isdir(target):
            return R('Invalid path.')
        lines = [
            'Directory PATH listing for Volume MS-DOS_6',
            'Volume serial number is 1992-0311',
            _to_dos_path(target),
        ]
        def _tree(path, prefix=''):
            try:
                entries = sorted(os.listdir(path))
            except PermissionError:
                return
            dirs  = [e for e in entries if os.path.isdir(os.path.join(path, e))]
            files = [e for e in entries if os.path.isfile(os.path.join(path, e))]
            all_e = dirs + (files if show_files else [])
            for i, name in enumerate(all_e):
                last = (i == len(all_e) - 1)
                conn = '\\---' if last else '+---'
                lines.append(f'{prefix}{conn}{name.upper()}')
                if os.path.isdir(os.path.join(path, name)):
                    ext = '    ' if last else '|   '
                    _tree(os.path.join(path, name), prefix + ext)
        _tree(target)
        return R('\n'.join(lines))

    # ── FORMAT ───────────────────────────────────────────────────────────────
    if cmd == 'FORMAT':
        return R('Format not supported in this environment.\nTo protect your data, FORMAT has been disabled.')

    # ── CHKDSK ───────────────────────────────────────────────────────────────
    if cmd == 'CHKDSK':
        usage  = shutil.disk_usage(DOS_ROOT)
        total  = 213_254_144
        used   = sum(os.path.getsize(os.path.join(r, f))
                     for r, _, fs in os.walk(DOS_ROOT) for f in fs)
        free   = total - used
        out = (
            f' Volume in drive C is MS-DOS_6\n'
            f' Volume Serial Number is 1992-0311\n\n'
            f'213,254,144 bytes total disk space\n'
            f'      73,728 bytes in {sum(1 for r,d,f in os.walk(DOS_ROOT) for _ in d)} directories\n'
            f'    {used:>10,} bytes in {sum(1 for r,d,fs in os.walk(DOS_ROOT) for _ in fs)} user files\n'
            f'    {free:>10,} bytes available on disk\n\n'
            f'       4,096 bytes in each allocation unit\n'
            f'      52,063 total allocation units on disk\n'
            f'      {free//4096:>5,} available allocation units on disk\n\n'
            f'      655,360 total bytes memory\n'
            f'      517,072 bytes free'
        )
        return R(out)

    # ── SCANDISK ─────────────────────────────────────────────────────────────
    if cmd == 'SCANDISK':
        out = (
            'Microsoft ScanDisk\n'
            '\n'
            'ScanDisk is now checking drive C.\n'
            '\n'
            '  Checking file allocation table ...\n'
            '  Checking directory structure ...\n'
            '  Checking file system ...\n'
            '  Checking surface scan ...\n'
            '\n'
            'ScanDisk found no problems on drive C.\n'
            '213,254,144 bytes total disk space\n'
            '  No bad sectors'
        )
        return R(out)

    # ── DEFRAG ───────────────────────────────────────────────────────────────
    if cmd == 'DEFRAG':
        out = (
            'Microsoft Defragmenter\n'
            'Copyright (C) Microsoft Corp 1981-1994\n'
            '\n'
            'Optimizing drive C...\n'
            '\n'
            '  Reading file allocation table ...\n'
            '  Defragmenting files ...\n'
            '  Compacting free space ...\n'
            '\n'
            '  [████████████████████████] 100%\n'
            '\n'
            'Defragmentation complete.\n'
            '  0% fragmented'
        )
        return R(out)

    # ── MSD ──────────────────────────────────────────────────────────────────
    if cmd == 'MSD':
        out = (
            'Microsoft Diagnostics Version 2.01\n'
            '\n'
            'Computer:      MS-DOS Compatible\n'
            'Memory:        640K Conventional, 15,360K Extended\n'
            'Video:         VGA, 640x480, 16 colors\n'
            'Network:       No network detected\n'
            'OS Version:    MS-DOS 6.22\n'
            'Mouse:         Microsoft compatible\n'
            'Disk Drives:   C: 213MB (Fixed)\n'
            'LPT Ports:     LPT1\n'
            'COM Ports:     COM1, COM2\n'
            'IRQ Status:    IRQ1=Keyboard, IRQ3=COM2, IRQ4=COM1\n'
            'BIOS:          Phoenix ROM BIOS PLUS Version 1.10 A03\n'
            'Processor:     486DX/33MHz, FPU present'
        )
        return R(out)

    # ── UNDELETE ─────────────────────────────────────────────────────────────
    if cmd == 'UNDELETE':
        return R(
            'UNDELETE - Undelete Protection Method\n'
            '\n'
            'Directory: ' + dos_cwd + '\n'
            'File specifications: *.*\n'
            '\n'
            '     0 file(s) available for recovery.\n'
            '\n'
            'No deleted files were found.'
        )

    # ── EDIT / NOTEPAD ───────────────────────────────────────────────────────
    if cmd in ('EDIT', 'NOTEPAD', 'NOTEPAD.EXE'):
        if not args:
            return R(meta={'edit': None})
        target = _resolve(dos_cwd, args)
        if target is None:
            return R('Access denied.')
        # Create the file if it doesn't exist
        if not os.path.exists(target):
            os.makedirs(os.path.dirname(target), exist_ok=True)
            open(target, 'w').close()
        return R(meta={'edit': _to_dos_path(target)})

    # ── SUBST ────────────────────────────────────────────────────────────────
    if cmd == 'SUBST':
        return R('No substitutions.')

    # ── LOADHIGH / LH ────────────────────────────────────────────────────────
    if cmd in ('LOADHIGH', 'LH'):
        return R(f'Loading {args.upper()} into upper memory...\nLoaded successfully.')

    # ── HELP ─────────────────────────────────────────────────────────────────
    if cmd == 'HELP':
        topics = {
            'ATTRIB':  'ATTRIB [file] [/S]         Display or change file attributes.\n'
                       '  /S  Process subdirectories',
            'BREAK':   'BREAK [ON|OFF]              Enable/disable CTRL+C checking.',
            'CHCP':    'CHCP [nnn]                  Display or set the active code page.',
            'CHKDSK':  'CHKDSK [drive:] [/F] [/V]  Check disk and display status.\n'
                       '  /F  Fix errors  /V  Verbose',
            'CLS':     'CLS                         Clear the screen.',
            'COLOR':   'COLOR [attr]                Set terminal foreground/background colors.\n'
                       '  attr is two hex digits: background foreground\n'
                       '  0=Black 1=Blue 2=Green 3=Cyan 4=Red 5=Magenta\n'
                       '  6=Yellow 7=White 8=Gray 9=Lt.Blue A=Lt.Green\n'
                       '  B=Lt.Cyan C=Lt.Red D=Lt.Magenta E=Yellow F=Br.White\n'
                       '  Example: COLOR 1F (blue bg, bright white fg)\n'
                       '           COLOR 0A (black bg, green fg)',
            'COPY':    'COPY src dst [/V] [/Y]      Copy file(s).\n'
                       '  /V  Verify after copy  /Y  Overwrite without prompt\n'
                       '  Supports wildcards: COPY *.TXT DOCS',
            'DATE':    'DATE                        Display current date.',
            'DEFRAG':  'DEFRAG [drive]              Defragment the drive.',
            'DEL':     'DEL filename [/S] [/F] [/Q] Delete file(s).\n'
                       '  /S  Delete from subdirectories  /F  Force read-only\n'
                       '  /Q  Quiet (no confirmation)  Supports wildcards: DEL *.BAK',
            'DELTREE': 'DELTREE path                Delete directory tree (no confirmation).',
            'DIR':     'DIR [path] [/W] [/B] [/S] [/A[:D]] [/O[:NSDE-]] [/L]\n'
                       '  /W  Wide format  /B  Bare filenames only\n'
                       '  /S  Include subdirectories  /A:D  Directories only\n'
                       '  /O:N Sort by name  /O:S by size  /O:D by date  /O:E by ext\n'
                       '  /O:-N Reverse sort  /L  Lowercase output',
            'DOSKEY':  'DOSKEY                      Show DOSKEY status (UP/DOWN arrow history).',
            'ECHO':    'ECHO [message|ON|OFF]        Display message or toggle echo.',
            'EDIT':    'EDIT [filename]              Open file in text editor.',
            'EXIT':    'EXIT                         Close MS-DOS prompt.',
            'ERASE':   'ERASE filename               Same as DEL.',
            'FC':      'FC file1 file2 [/B] [/L] [/N]  Compare two files.\n'
                       '  /B  Binary compare  /L  ASCII compare  /N  Show line numbers',
            'FIND':    'FIND [/V] [/C] [/N] [/I] "string" filename...\n'
                       '  /V  Lines NOT containing  /C  Count only\n'
                       '  /N  Show line numbers  /I  Case-insensitive',
            'FORMAT':  'FORMAT drive:               (Disabled in this environment)',
            'LABEL':   'LABEL [label]               Change the volume label.',
            'MD':      'MD path                     Create directory (same as MKDIR).',
            'MEM':     'MEM [/C]                    Display memory usage.\n'
                       '  /C  Classify modules using memory',
            'MORE':    'MORE filename               Display file one screen at a time.',
            'MOVE':    'MOVE src dst                Move or rename file(s).',
            'MSD':     'MSD                         Microsoft Diagnostics — system information.',
            'PATH':    'PATH [path]                 Display or set executable search path.',
            'PAUSE':   'PAUSE                       Suspend processing and display a message.',
            'PROMPT':  'PROMPT [text]               Change command prompt display.',
            'RD':      'RD path [/S] [/Q]           Remove directory.\n'
                       '  /S  Remove with all contents  /Q  Quiet mode',
            'REM':     'REM [comment]               Comment in batch files (no output).',
            'REN':     'REN oldname newname          Rename a file or directory.',
            'RENAME':  'RENAME oldname newname       Same as REN.',
            'RMDIR':   'RMDIR path [/S] [/Q]        Same as RD.',
            'SCANDISK':'SCANDISK [drive]             Scan disk for errors.',
            'SET':     'SET [var=value]              Display or set environment variables.',
            'SORT':    'SORT [/R] [/+n] filename    Sort file contents.\n'
                       '  /R  Reverse order  /+n  Sort from column n',
            'SUBST':   'SUBST                       Substitute path for drive letter.',
            'TIME':    'TIME                        Display current time.',
            'TITLE':   'TITLE text                  Set the MS-DOS window title.',
            'TREE':    'TREE [path] [/F]            Display directory tree.\n'
                       '  /F  Include files in listing',
            'TYPE':    'TYPE file [file2 ...]        Display file contents.\n'
                       '  Multiple files: TYPE FILE1.TXT FILE2.TXT',
            'UNDELETE':'UNDELETE [path]             Recover deleted files.',
            'VER':     'VER                         Display MS-DOS version.',
            'VERIFY':  'VERIFY [ON|OFF]             Set/display disk-write verification.',
            'VOL':     'VOL [drive:]                Display volume label.',
            'XCOPY':   'XCOPY src dst [/S] [/E] [/V] [/P] [/Y]  Extended copy.\n'
                       '  /S  Copy subdirectories  /E  Include empty directories\n'
                       '  /V  Verify  /P  Prompt before copy  /Y  Overwrite',
        }
        if args:
            key = args.strip().upper()
            topic = topics.get(key)
            return R(topic or f'No help available for {key}.')

        out = (
            'For more information on a specific command, type HELP command-name\n\n'
            'ATTRIB    BREAK     CHCP      CHKDSK    CLS\n'
            'COLOR     COPY      DATE      DEFRAG    DEL\n'
            'DELTREE   DIR       DOSKEY    ECHO      EDIT\n'
            'ERASE     EXIT      FC        FIND      FORMAT\n'
            'LABEL     MD        MEM       MKDIR     MORE\n'
            'MOVE      MSD       PATH      PAUSE     PROMPT\n'
            'RD        REM       REN       RENAME    RMDIR\n'
            'SCANDISK  SET       SORT      SUBST     TIME\n'
            'TITLE     TREE      TYPE      UNDELETE  VER\n'
            'VERIFY    VOL       XCOPY\n'
        )
        return R(out)

    # ── Unknown ───────────────────────────────────────────────────────────────
    return R(f"Bad command or file name\n'{cmd}' is not recognized as an internal or external command.\nType HELP for a list of commands.")


# ── Shared absolute-path resolver (for GUI endpoints) ─────────────────────────

def _resolve_absolute(dos_path: str):
    """Resolve a full DOS path like C:\\DOCS\\FILE.TXT to a real sandboxed path."""
    p = dos_path.strip().upper()
    if p.startswith('C:\\') or p.startswith('C:/'):
        rel = p[3:].replace('\\', os.sep).replace('/', os.sep)
        real = os.path.normpath(os.path.join(DOS_ROOT, rel)) if rel else DOS_ROOT
    elif p in ('C:', 'C://', 'C:\\\\'):
        real = DOS_ROOT
    else:
        return None
    return real if real.startswith(DOS_ROOT) else None


# ── Flask routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/time')
def get_time():
    now = datetime.datetime.now()
    return jsonify({'time': now.strftime('%I:%M %p'), 'date': now.strftime('%A, %B %d, %Y')})

# ── Virtual filesystem API (shared by File Manager and Notepad) ───────────────

@app.route('/api/fs/list')
def fs_list():
    _check_ip_session()
    dos_path = request.args.get('path', 'C:\\')
    real = _resolve_absolute(dos_path)
    if real is None or not os.path.isdir(real):
        return jsonify({'error': 'Invalid path'}), 400

    entries = []
    try:
        for name in sorted(os.listdir(real), key=lambda n: (not os.path.isdir(os.path.join(real, n)), n.upper())):
            full = os.path.join(real, name)
            st   = os.stat(full)
            entries.append({
                'name':     name.upper(),
                'is_dir':   os.path.isdir(full),
                'size':     0 if os.path.isdir(full) else st.st_size,
                'modified': datetime.datetime.fromtimestamp(st.st_mtime).strftime('%m/%d/%Y %I:%M %p'),
            })
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403

    # Build parent path
    parent = None
    if real != DOS_ROOT:
        parent_real = os.path.dirname(real)
        parent = _to_dos_path(parent_real)

    return jsonify({'path': _to_dos_path(real), 'parent': parent, 'entries': entries})


@app.route('/api/fs/read')
def fs_read():
    _check_ip_session()
    dos_path = request.args.get('path', '')
    real = _resolve_absolute(dos_path)
    if real is None or not os.path.isfile(real):
        return jsonify({'error': 'File not found'}), 404
    try:
        with open(real, 'r', errors='replace') as f:
            content = f.read()
        return jsonify({'content': content, 'path': _to_dos_path(real)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/fs/write', methods=['POST'])
def fs_write():
    _check_ip_session()
    data     = request.json
    dos_path = data.get('path', '').strip()
    content  = data.get('content', '')
    real = _resolve_absolute(dos_path)
    if real is None:
        return jsonify({'error': 'Invalid path'}), 400
    os.makedirs(os.path.dirname(real), exist_ok=True)
    with open(real, 'w', newline='') as f:
        f.write(content)

    with _db() as conn:
        conn.execute(
            'INSERT INTO notepad_log (ts, ip, path, content) VALUES (?,?,?,?)',
            (datetime.datetime.utcnow().isoformat(), _client_ip(), dos_path, content)
        )

    return jsonify({'status': 'saved', 'path': _to_dos_path(real)})

@app.route('/api/dos', methods=['POST'])
def dos_command():
    _check_ip_session()
    data    = request.json
    command = data.get('command', '').strip()
    cwd     = data.get('cwd', 'C:\\')

    # Sanitise cwd
    if not cwd.upper().startswith('C:\\'):
        cwd = 'C:\\'

    output, new_cwd, clear, exit_shell, meta = '', cwd, False, False, {}
    try:
        output, new_cwd, clear, exit_shell, meta = run_dos_command(command, cwd)
    finally:
        with _db() as conn:
            conn.execute(
                'INSERT INTO dos_log (ts, ip, command, cwd, output) VALUES (?,?,?,?,?)',
                (datetime.datetime.utcnow().isoformat(), _client_ip(), command, cwd, output)
            )

    return jsonify({'output': output, 'cwd': new_cwd, 'clear': clear, 'exit': exit_shell, 'meta': meta})

# ── QBasic routes ─────────────────────────────────────────────────────────────

QBASIC_DIR = os.path.join(DOS_ROOT, 'QBASIC')
os.makedirs(QBASIC_DIR, exist_ok=True)

def _qbasic_sid():
    if 'qb_sid' not in session:
        import uuid
        session['qb_sid'] = str(uuid.uuid4())
    return session['qb_sid']

@app.route('/api/qbasic/run', methods=['POST'])
def qbasic_run():
    _check_ip_session()
    data   = request.json
    code   = data.get('code', '')
    inputs = data.get('inputs', [])
    sid    = data.get('sid', 'default')

    interp = BASICInterpreter()
    try:
        interp.load(code)
        lines = interp.run(inputs)
    except InputNeeded as e:
        with _db() as conn:
            conn.execute(
                'INSERT INTO qbasic_log (ts, ip, event, code, output) VALUES (?,?,?,?,?)',
                (datetime.datetime.utcnow().isoformat(), _client_ip(), 'run', code, '\n'.join(interp.output_lines))
            )
        return jsonify({'output': interp.output_lines, 'needs_input': True, 'prompt': e.prompt})
    except Exception as e:
        return jsonify({'output': interp.output_lines + [f'*** Internal error: {e}'], 'needs_input': False})

    with _db() as conn:
        conn.execute(
            'INSERT INTO qbasic_log (ts, ip, event, code, output) VALUES (?,?,?,?,?)',
            (datetime.datetime.utcnow().isoformat(), _client_ip(), 'run', code, '\n'.join(lines))
        )

    # Store interpreter state for immediate window use
    _interp_pool[sid] = interp
    return jsonify({'output': lines, 'needs_input': False, 'prompt': ''})


@app.route('/api/qbasic/immediate', methods=['POST'])
def qbasic_immediate():
    _check_ip_session()
    data  = request.json
    stmt  = data.get('stmt', '')
    inputs= data.get('inputs', [])
    sid   = data.get('sid', 'default')

    interp = _get_interp(sid)
    try:
        lines = interp.run_immediate(stmt, inputs)
    except InputNeeded as e:
        return jsonify({'output': interp.output_lines, 'needs_input': True, 'prompt': e.prompt})
    except Exception as e:
        return jsonify({'output': [f'*** {e}'], 'needs_input': False})

    return jsonify({'output': lines, 'needs_input': False, 'prompt': ''})


@app.route('/api/qbasic/reset', methods=['POST'])
def qbasic_reset():
    _check_ip_session()
    sid = request.json.get('sid', 'default')
    _interp_pool.pop(sid, None)
    return jsonify({'ok': True})


@app.route('/api/qbasic/load')
def qbasic_load():
    _check_ip_session()
    filename = request.args.get('file', '')
    if not filename:
        return jsonify({'error': 'No filename'}), 400
    safe = os.path.basename(filename).upper()
    path = os.path.join(QBASIC_DIR, safe)
    if not os.path.isfile(path):
        # Also search dos_root
        alt = _resolve_absolute('C:\\' + filename.lstrip('C:\\').lstrip('/'))
        if alt and os.path.isfile(alt):
            path = alt
        else:
            return jsonify({'error': 'File not found'}), 404
    with open(path, 'r', errors='replace') as f:
        return jsonify({'code': f.read(), 'filename': safe})


@app.route('/api/qbasic/save', methods=['POST'])
def qbasic_save():
    _check_ip_session()
    data     = request.json
    code     = data.get('code', '')
    filename = os.path.basename(data.get('filename', 'UNTITLED.BAS')).upper()
    if not filename.endswith('.BAS'):
        filename += '.BAS'
    path = os.path.join(QBASIC_DIR, filename)
    with open(path, 'w') as f:
        f.write(code)

    with _db() as conn:
        conn.execute(
            'INSERT INTO qbasic_log (ts, ip, event, filename, code) VALUES (?,?,?,?,?)',
            (datetime.datetime.utcnow().isoformat(), _client_ip(), 'save', filename, code)
        )
    return jsonify({'ok': True, 'filename': filename, 'path': 'C:\\QBASIC\\' + filename})


@app.route('/api/qbasic/files')
def qbasic_files():
    files = [f for f in os.listdir(QBASIC_DIR) if f.upper().endswith('.BAS')]
    return jsonify({'files': sorted(files)})


if __name__ == '__main__':
    app.run(debug=True)
