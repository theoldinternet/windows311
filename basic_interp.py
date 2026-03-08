"""
MS-BASIC / QBasic compatible interpreter.
Supports: PRINT, INPUT, LET, IF/THEN/ELSE/END IF, FOR/NEXT, WHILE/WEND,
DO/LOOP, GOTO, GOSUB/RETURN, DIM, SELECT CASE, DATA/READ/RESTORE,
SWAP, RANDOMIZE, CLS, BEEP, SLEEP, END, STOP, REM, and all common
math / string built-in functions.
"""
import re, math, random, time as _time

# ── Exceptions ────────────────────────────────────────────────────────────────

class BASICError(Exception):
    pass

class _Goto(Exception):
    def __init__(self, target): self.target = target

class _Gosub(Exception):
    def __init__(self, target): self.target = target

class _Return(Exception): pass
class _End(Exception): pass
class _Stop(Exception): pass

class InputNeeded(Exception):
    def __init__(self, prompt='? '): self.prompt = prompt

# ── Tokeniser helpers ─────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r'"[^"]*"'                       # string literal
    r'|(?<![A-Za-z0-9_$%!#])(AND|OR|NOT|MOD|XOR)\b'  # logical/mod ops
    r'|[A-Za-z_][A-Za-z0-9_]*[$%!#]?'  # identifier / keyword
    r'|[0-9]*\.?[0-9]+(?:[Ee][+-]?[0-9]+)?'  # number
    r'|<>|<=|>=|[+\-*/\\^=<>(),;:#&]'  # operators & punctuation
    , re.IGNORECASE
)

def _tokenise(s):
    return [m.group() for m in _TOKEN_RE.finditer(s)]

def _split_on(tokens, sep):
    """Split token list on a top-level separator (respects parentheses)."""
    parts, cur, depth = [], [], 0
    for t in tokens:
        if t == '(' : depth += 1
        elif t == ')': depth -= 1
        if t.upper() == sep.upper() and depth == 0:
            parts.append(cur); cur = []
        else:
            cur.append(t)
    parts.append(cur)
    return parts

def _join(tokens): return ' '.join(tokens)

# ── Expression evaluator ──────────────────────────────────────────────────────

class Expr:
    """Recursive-descent expression evaluator."""

    def __init__(self, interp):
        self.I = interp   # reference to interpreter for variables / functions

    def eval(self, tokens):
        val, pos = self._or(tokens, 0)
        return val

    # Precedence: OR < AND < NOT < comparison < &(concat) < +/- < */\ < MOD < ^ < unary < atom

    def _or(self, tk, p):
        left, p = self._and(tk, p)
        while p < len(tk) and tk[p].upper() == 'OR':
            right, p = self._and(tk, p+1)
            left = -1 if (self._truth(left) or self._truth(right)) else 0
        return left, p

    def _and(self, tk, p):
        left, p = self._not(tk, p)
        while p < len(tk) and tk[p].upper() == 'AND':
            right, p = self._not(tk, p+1)
            left = -1 if (self._truth(left) and self._truth(right)) else 0
        return left, p

    def _not(self, tk, p):
        if p < len(tk) and tk[p].upper() == 'NOT':
            val, p = self._not(tk, p+1)
            return (0 if self._truth(val) else -1), p
        return self._xor(tk, p)

    def _xor(self, tk, p):
        left, p = self._compare(tk, p)
        while p < len(tk) and tk[p].upper() == 'XOR':
            right, p = self._compare(tk, p+1)
            left = -1 if (self._truth(left) ^ self._truth(right)) else 0
        return left, p

    def _compare(self, tk, p):
        left, p = self._concat(tk, p)
        ops = {'=', '<>', '<', '>', '<=', '>='}
        while p < len(tk) and tk[p] in ops:
            op = tk[p]; p += 1
            right, p = self._concat(tk, p)
            left = self._cmp(op, left, right)
        return left, p

    def _cmp(self, op, a, b):
        try:
            fa, fb = float(a), float(b)
            a, b = fa, fb
        except (TypeError, ValueError):
            a, b = str(a), str(b)
        result = {'=': a==b, '<>': a!=b, '<': a<b, '>': a>b,
                  '<=': a<=b, '>=': a>=b}[op]
        return -1 if result else 0

    def _concat(self, tk, p):
        left, p = self._add(tk, p)
        while p < len(tk) and tk[p] == '&':
            right, p = self._add(tk, p+1)
            left = str(left) + str(right)
        return left, p

    def _add(self, tk, p):
        left, p = self._mul(tk, p)
        while p < len(tk) and tk[p] in ('+', '-'):
            op = tk[p]; p += 1
            right, p = self._mul(tk, p)
            if op == '+':
                # string concat via +
                try:
                    left = self._num(left) + self._num(right)
                except (TypeError, ValueError):
                    left = str(left) + str(right)
            else:
                left = self._num(left) - self._num(right)
        return left, p

    def _mul(self, tk, p):
        left, p = self._mod(tk, p)
        while p < len(tk) and tk[p] in ('*', '/', '\\'):
            op = tk[p]; p += 1
            right, p = self._mod(tk, p)
            if op == '*':  left = self._num(left) * self._num(right)
            elif op == '/':
                r = self._num(right)
                if r == 0: raise BASICError('Division by zero')
                left = self._num(left) / r
            else:  # integer division
                r = int(self._num(right))
                if r == 0: raise BASICError('Division by zero')
                left = int(self._num(left)) // r
        return left, p

    def _mod(self, tk, p):
        left, p = self._pow(tk, p)
        while p < len(tk) and tk[p].upper() == 'MOD':
            right, p = self._pow(tk, p+1)
            r = self._num(right)
            if r == 0: raise BASICError('Division by zero')
            left = self._num(left) % r
        return left, p

    def _pow(self, tk, p):
        left, p = self._unary(tk, p)
        if p < len(tk) and tk[p] == '^':
            right, p = self._pow(tk, p+1)   # right-associative
            left = self._num(left) ** self._num(right)
        return left, p

    def _unary(self, tk, p):
        if p < len(tk) and tk[p] == '-':
            val, p = self._unary(tk, p+1)
            return -self._num(val), p
        if p < len(tk) and tk[p] == '+':
            val, p = self._unary(tk, p+1)
            return self._num(val), p
        return self._atom(tk, p)

    def _atom(self, tk, p):
        if p >= len(tk):
            raise BASICError('Unexpected end of expression')
        t = tk[p]

        # String literal
        if t.startswith('"'):
            return t[1:-1], p+1

        # Numeric literal
        try:
            v = float(t)
            return (int(v) if v == int(v) else v), p+1
        except ValueError:
            pass

        # Parenthesised expression
        if t == '(':
            val, p2 = self._or(tk, p+1)
            if p2 >= len(tk) or tk[p2] != ')':
                raise BASICError('Missing )')
            return val, p2+1

        # Identifier / function / array
        name = t.upper()

        # Built-in functions
        if name in self.I.FUNCTIONS:
            return self._call_func(name, tk, p+1)

        # Variable (scalar or array)
        p += 1
        if p < len(tk) and tk[p] == '(':
            # Array access
            args, p = self._arg_list(tk, p)
            idx = tuple(int(self._num(a)) for a in args)
            arr = self.I.arrays.get(t.upper(), {})
            val = arr.get(idx, 0)
            return val, p

        # Scalar variable
        val = self.I.vars.get(t.upper(), '' if t.endswith('$') else 0)
        return val, p

    def _arg_list(self, tk, p):
        """Parse (arg, arg, ...) starting at '(' token. Returns (args_list, new_p)."""
        assert tk[p] == '('
        p += 1
        args = []
        if p < len(tk) and tk[p] == ')':
            return args, p+1
        while True:
            val, p = self._or(tk, p)
            args.append(val)
            if p >= len(tk) or tk[p] != ',':
                break
            p += 1
        if p >= len(tk) or tk[p] != ')':
            raise BASICError('Missing ) in argument list')
        return args, p+1

    def _call_func(self, name, tk, p):
        # p points to character AFTER function name
        if p >= len(tk) or tk[p] != '(':
            # Zero-arg functions
            if name == 'RND':
                return random.random(), p
            if name in ('TIMER', 'TIMER#'):
                return _time.time() % 86400, p
            if name == 'INKEY$':
                return '', p
            if name == 'DATE$':
                import datetime
                return _time.strftime('%m-%d-%Y'), p
            if name == 'TIME$':
                return _time.strftime('%H:%M:%S'), p
            raise BASICError(f'Expected ( after {name}')
        args, p = self._arg_list(tk, p)
        return self.I.FUNCTIONS[name](args), p

    def _truth(self, v):
        try: return float(v) != 0
        except (TypeError, ValueError): return bool(v)

    def _num(self, v):
        if isinstance(v, (int, float)): return v
        try: return int(v)
        except (ValueError, TypeError):
            try: return float(v)
            except (ValueError, TypeError):
                raise BASICError(f'Type mismatch: expected number, got {v!r}')


# ── Main interpreter ──────────────────────────────────────────────────────────

class BASICInterpreter:

    KEYWORDS = {
        'PRINT','INPUT','LET','IF','THEN','ELSE','ELSEIF','END','FOR','TO',
        'STEP','NEXT','WHILE','WEND','DO','LOOP','UNTIL','GOTO','GOSUB',
        'RETURN','DIM','REM','DATA','READ','RESTORE','CLS','BEEP','SLEEP',
        'SWAP','RANDOMIZE','SELECT','CASE','STOP','AND','OR','NOT','MOD',
        'XOR','LINE','SUB','FUNCTION','CALL','EXIT',
    }

    def __init__(self):
        self.vars = {}
        self.arrays = {}
        self.array_dims = {}
        self.output_lines = []
        self._print_buf = ''        # partial line buffer for ; separator
        self.input_queue = []
        self.call_stack = []        # GOSUB return PCs
        self.for_stack = []         # ForFrame dicts
        self.do_stack = []          # DO loop start PCs
        self.while_stack = []       # WHILE loop start PCs
        self.select_stack = []      # SELECT CASE value stack
        self.data_values = []
        self.data_ptr = 0
        self.program = []           # [(lineno_or_None, stmt_str), ...]
        self.line_map = {}          # line_number -> index
        self.label_map = {}         # label_str -> index
        self.pc = 0
        self._iters = 0
        self.FUNCTIONS = self._build_functions()
        self._expr = Expr(self)

    # ── Functions table ────────────────────────────────────────────────────

    def _build_functions(self):
        def _n(args, i=0): return float(args[i]) if isinstance(args[i],(int,float)) else float(str(args[i]))
        def _s(args, i=0): return str(args[i])
        def _i(args, i=0): return int(_n(args,i))
        F = {}
        F['ABS']  = lambda a: abs(_n(a))
        F['INT']  = lambda a: math.floor(_n(a))
        F['FIX']  = lambda a: int(_n(a))
        F['CINT'] = lambda a: round(_n(a))
        F['CLNG'] = lambda a: int(round(_n(a)))
        F['CSNG'] = lambda a: float(_n(a))
        F['SGN']  = lambda a: (1 if _n(a)>0 else -1 if _n(a)<0 else 0)
        F['SQR']  = lambda a: math.sqrt(max(0,_n(a)))
        F['SIN']  = lambda a: math.sin(_n(a))
        F['COS']  = lambda a: math.cos(_n(a))
        F['TAN']  = lambda a: math.tan(_n(a))
        F['ATN']  = lambda a: math.atan(_n(a))
        F['LOG']  = lambda a: math.log(max(1e-300,_n(a)))
        F['EXP']  = lambda a: math.exp(min(_n(a), 709))
        F['RND']  = lambda a: (random.random() if not a or _n(a)!=0 else random.random())
        F['TIMER']= lambda a: _time.time() % 86400
        F['LEN']  = lambda a: len(_s(a))
        F['ASC']  = lambda a: ord(_s(a)[0]) if _s(a) else 0
        F['CHR$'] = lambda a: chr(int(_n(a)))
        F['STR$'] = lambda a: (' '+str(int(_n(a))) if _n(a)==int(_n(a)) else ' '+str(_n(a)))
        F['VAL']  = lambda a: (lambda s: (float(s) if '.' in s or 'e' in s.lower() else int(s)) if s else 0)(re.match(r'[+-]?[0-9]*\.?[0-9]+(?:[Ee][+-]?[0-9]+)?',_s(a).strip()) and re.match(r'[+-]?[0-9]*\.?[0-9]+(?:[Ee][+-]?[0-9]+)?',_s(a).strip()).group() or '0')
        F['UCASE$'] = lambda a: _s(a).upper()
        F['LCASE$'] = lambda a: _s(a).lower()
        F['LTRIM$'] = lambda a: _s(a).lstrip()
        F['RTRIM$'] = lambda a: _s(a).rstrip()
        F['TRIM$']  = lambda a: _s(a).strip()
        F['LEFT$']  = lambda a: _s(a)[:_i(a,1)]
        F['RIGHT$'] = lambda a: _s(a)[max(0,len(_s(a))-_i(a,1)):]
        F['MID$']   = lambda a: (_s(a)[_i(a,1)-1:_i(a,1)-1+_i(a,2)] if len(a)>=3 else _s(a)[_i(a,1)-1:])
        F['SPACE$'] = lambda a: ' '*max(0,_i(a))
        F['STRING$']= lambda a: (chr(int(_n(a,1))) if isinstance(a[1],str) else chr(_i(a,1)))*max(0,_i(a))
        F['HEX$']   = lambda a: hex(int(_n(a)))[2:].upper()
        F['OCT$']   = lambda a: oct(int(_n(a)))[2:]
        F['INSTR']  = lambda a: ((_s(a,1).find(_s(a,2))+1) if len(a)==2 else (_s(a,1)[_i(a)-1:].find(_s(a,2))+_i(a) if _s(a,1)[_i(a)-1:].find(_s(a,2))>=0 else 0))
        F['DATE$']  = lambda a: _time.strftime('%m-%d-%Y')
        F['TIME$']  = lambda a: _time.strftime('%H:%M:%S')
        return F

    # ── Load program ───────────────────────────────────────────────────────

    def load(self, code: str):
        self.program = []
        self.line_map = {}
        self.label_map = {}
        self.data_values = []
        self.data_ptr = 0

        for raw in code.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped:
                self.program.append((None, ''))
                continue

            # Line number prefix
            m = re.match(r'^(\d+)\s*(.*)', stripped)
            if m:
                lineno, stmt = int(m.group(1)), m.group(2)
                self.line_map[lineno] = len(self.program)
                self.program.append((lineno, stmt))
            else:
                # Label?
                m2 = re.match(r'^([A-Za-z_]\w*)\s*:\s*(.*)', stripped)
                if m2 and m2.group(1).upper() not in self.KEYWORDS:
                    lbl = m2.group(1).upper()
                    self.label_map[lbl] = len(self.program)
                    self.program.append((None, m2.group(2)))
                else:
                    self.program.append((None, stripped))

            # Pre-scan DATA
            s = self.program[-1][1].strip()
            if re.match(r'^DATA\b', s, re.IGNORECASE):
                self._scan_data(s[4:].strip())

    def _scan_data(self, rest):
        for item in self._csv_split(rest):
            item = item.strip()
            if item.startswith('"') and item.endswith('"'):
                self.data_values.append(item[1:-1])
            else:
                try:
                    v = float(item)
                    self.data_values.append(int(v) if v == int(v) else v)
                except ValueError:
                    self.data_values.append(item)

    # ── Run ────────────────────────────────────────────────────────────────

    def run(self, inputs=None):
        self.input_queue = list(inputs or [])
        self.output_lines = []
        self._print_buf = ''
        self.call_stack = []
        self.for_stack = []
        self.do_stack = []
        self.while_stack = []
        self.select_stack = []
        self.data_ptr = 0
        self.pc = 0
        self._iters = 0

        try:
            while 0 <= self.pc < len(self.program):
                _, stmt = self.program[self.pc]
                self.pc += 1
                self._exec(stmt.strip())
                self._iters += 1
                if self._iters > 500_000:
                    self._flush()
                    self.output_lines.append('*** Program halted: maximum iterations exceeded')
                    break
        except _End:
            pass
        except _Stop:
            self._flush()
            self.output_lines.append('*** Break in program')
        except BASICError as e:
            self._flush()
            self.output_lines.append(f'*** Runtime error: {e}')
        except InputNeeded:
            raise

        self._flush()
        return self.output_lines

    def run_immediate(self, stmt: str, inputs=None):
        """Execute one statement, keeping variable state."""
        self.input_queue = list(inputs or [])
        self.output_lines = []
        self._print_buf = ''
        self._iters = 0
        try:
            self._exec(stmt.strip())
        except (_End, _Stop):
            pass
        except BASICError as e:
            self.output_lines.append(f'*** {e}')
        except InputNeeded:
            raise
        self._flush()
        return self.output_lines

    # ── Statement dispatcher ───────────────────────────────────────────────

    def _exec(self, stmt: str):
        if not stmt:
            return
        # Handle multiple colon-separated statements on one line
        # (but not inside strings)
        stmts = self._colon_split(stmt)
        if len(stmts) > 1:
            for s in stmts:
                self._exec(s.strip())
            return

        # Inline comment removal
        stmt = self._strip_comment(stmt)
        if not stmt:
            return

        # Detect keyword
        upper = stmt.upper()
        kw, rest = self._split_kw(stmt)

        if kw == 'REM' or stmt.startswith("'"):
            return

        elif kw == 'PRINT':
            self._exec_print(rest)

        elif kw in ('INPUT', 'LINE'):
            if kw == 'LINE' and rest.upper().startswith('INPUT'):
                rest = rest[5:].strip()
                self._exec_input(rest, line_input=True)
            elif kw == 'INPUT':
                self._exec_input(rest)

        elif kw == 'LET':
            self._exec_let(rest)

        elif kw == 'IF':
            self._exec_if(rest)

        elif kw in ('ELSEIF', 'ELSE'):
            # Skip to END IF
            self._scan_forward(['END IF'], nesting_open=['IF'], nesting_close=['END IF'])

        elif kw == 'END':
            sub = rest.strip().upper()
            if sub == 'IF':
                return  # just a block closer
            elif sub == 'SELECT':
                if self.select_stack:
                    self.select_stack.pop()
                return
            elif sub == '':
                raise _End()
            else:
                raise _End()

        elif kw == 'FOR':
            self._exec_for(rest)

        elif kw == 'NEXT':
            self._exec_next(rest)

        elif kw == 'WHILE':
            self._exec_while(rest)

        elif kw == 'WEND':
            self._exec_wend()

        elif kw == 'DO':
            self._exec_do(rest)

        elif kw == 'LOOP':
            self._exec_loop(rest)

        elif kw == 'GOTO':
            self._exec_goto(rest.strip())

        elif kw == 'GOSUB':
            self._exec_gosub(rest.strip())

        elif kw == 'RETURN':
            self._exec_return()

        elif kw == 'DIM':
            self._exec_dim(rest)

        elif kw == 'DATA':
            return  # already pre-scanned

        elif kw == 'READ':
            self._exec_read(rest)

        elif kw == 'RESTORE':
            self.data_ptr = 0

        elif kw == 'SWAP':
            self._exec_swap(rest)

        elif kw == 'RANDOMIZE':
            seed = rest.strip().upper()
            if seed == 'TIMER' or not seed:
                random.seed()
            else:
                random.seed(int(self._eval(seed)))

        elif kw == 'CLS':
            self._flush()
            self.output_lines.append('\x0c')   # form-feed = clear signal

        elif kw == 'BEEP':
            pass  # handled client-side via meta

        elif kw == 'SLEEP':
            pass  # ignore sleep in server-side execution

        elif kw == 'STOP':
            raise _Stop()

        elif kw == 'END':
            raise _End()

        elif kw == 'EXIT':
            sub = rest.strip().upper()
            if sub == 'FOR':
                self._exit_for()
            elif sub in ('DO', 'LOOP'):
                self._exit_do()
            elif sub in ('WHILE',):
                self._exit_while()

        elif kw == 'SELECT':
            self._exec_select(rest)

        elif kw == 'CASE':
            self._exec_case(rest)

        elif kw in ('SUB', 'FUNCTION', 'CALL'):
            return  # basic sub stubs

        else:
            # Implicit assignment  VAR = expr  or  VAR(idx) = expr
            if '=' in stmt:
                self._exec_let(stmt)
            else:
                raise BASICError(f"Unrecognised statement: '{stmt}'")

    # ── PRINT ─────────────────────────────────────────────────────────────

    def _exec_print(self, rest):
        rest = rest.strip()
        if not rest:
            self._flush()
            return

        tokens = _tokenise(rest)
        items = self._print_items(tokens)

        for val, sep in items:
            s = self._to_str(val)
            if sep == ',':
                # Tab to next 14-char column
                col = len(self._print_buf)
                pad = 14 - (col % 14)
                self._print_buf += s + ' ' * pad
            else:
                self._print_buf += s

        # Last separator
        last_sep = items[-1][1] if items else None
        if last_sep not in (';', ','):
            self._flush()

    def _print_items(self, tokens):
        """Parse print list into [(value, sep)] where sep is ;, , or None."""
        items = []
        i = 0
        while i < len(tokens):
            # Check for bare separator
            if tokens[i] in (';', ','):
                if items:
                    old_val, _ = items[-1]
                    items[-1] = (old_val, tokens[i])
                i += 1
                continue
            # Collect tokens up to next ; or ,
            start = i
            depth = 0
            while i < len(tokens):
                if tokens[i] == '(': depth += 1
                elif tokens[i] == ')': depth -= 1
                elif tokens[i] in (';', ',') and depth == 0:
                    break
                i += 1
            sub = tokens[start:i]
            if sub:
                val = self._expr.eval(sub)
                sep = tokens[i] if i < len(tokens) else None
                items.append((val, sep))
                if sep in (';', ','):
                    i += 1
        return items if items else [('' , None)]

    def _to_str(self, v):
        if isinstance(v, bool): return '-1' if v else '0'
        if isinstance(v, int): return (' ' if v >= 0 else '') + str(v) + ' '
        if isinstance(v, float):
            if v == int(v) and abs(v) < 1e15:
                return (' ' if v >= 0 else '') + str(int(v)) + ' '
            return (' ' if v >= 0 else '') + str(v) + ' '
        return str(v)

    def _flush(self):
        self.output_lines.append(self._print_buf)
        self._print_buf = ''

    # ── INPUT ─────────────────────────────────────────────────────────────

    def _exec_input(self, rest, line_input=False):
        # Parse: ["prompt" [;|,]] varlist
        prompt = '? '
        rest = rest.strip()

        m = re.match(r'^"([^"]*)"\s*([;,]?)\s*(.*)', rest)
        if m:
            prompt = m.group(1)
            if m.group(2) == ';':
                prompt += '? '
            rest = m.group(3)

        varnames = [v.strip() for v in rest.split(',')]

        for vname in varnames:
            if not self.input_queue:
                # Need to ask the client for input
                raise InputNeeded(prompt)
            val = self.input_queue.pop(0)
            # Type coercion
            vn = vname.upper()
            if vn.endswith('$'):
                self.vars[vn] = str(val)
            else:
                try:
                    fv = float(val)
                    self.vars[vn] = int(fv) if fv == int(fv) else fv
                except (ValueError, TypeError):
                    self.vars[vn] = 0
            prompt = '? '

    # ── LET / assignment ──────────────────────────────────────────────────

    def _exec_let(self, rest):
        rest = rest.strip()
        # Find top-level =
        tokens = _tokenise(rest)
        eq = None
        depth = 0
        for i, t in enumerate(tokens):
            if t == '(': depth += 1
            elif t == ')': depth -= 1
            elif t == '=' and depth == 0:
                eq = i; break
        if eq is None:
            raise BASICError(f'Syntax error in assignment: {rest}')
        lhs = tokens[:eq]
        rhs = tokens[eq+1:]
        val = self._expr.eval(rhs)
        self._assign(lhs, val)

    def _assign(self, lhs_tokens, val):
        if len(lhs_tokens) == 1:
            vn = lhs_tokens[0].upper()
            if vn.endswith('$'):
                self.vars[vn] = str(val)
            else:
                self.vars[vn] = self._coerce_num(val)
        elif len(lhs_tokens) >= 4 and lhs_tokens[1] == '(':
            # Array assignment
            arrname = lhs_tokens[0].upper()
            idx_tokens = lhs_tokens[2:-1]
            parts = _split_on(idx_tokens, ',')
            idx = tuple(int(self._expr.eval(p)) for p in parts)
            if arrname not in self.arrays:
                self.arrays[arrname] = {}
            if arrname.endswith('$'):
                self.arrays[arrname][idx] = str(val)
            else:
                self.arrays[arrname][idx] = self._coerce_num(val)
        else:
            raise BASICError(f'Invalid assignment target')

    def _coerce_num(self, val):
        if isinstance(val, (int, float)): return val
        try:
            fv = float(val)
            return int(fv) if fv == int(fv) else fv
        except (ValueError, TypeError):
            return 0

    # ── IF ────────────────────────────────────────────────────────────────

    def _exec_if(self, rest):
        # Split on THEN (top-level only)
        tokens = _tokenise(rest)
        then_idx = None
        depth = 0
        for i, t in enumerate(tokens):
            if t == '(': depth += 1
            elif t == ')': depth -= 1
            elif t.upper() == 'THEN' and depth == 0:
                then_idx = i; break
        if then_idx is None:
            raise BASICError('IF without THEN')

        cond_tokens = tokens[:then_idx]
        after_then  = tokens[then_idx+1:]

        cond = self._expr.eval(cond_tokens)
        truth = (cond != 0 and cond != '' and cond is not False)

        if after_then:
            # Single-line IF
            after_str = _join(after_then)
            # Find ELSE at top level
            else_idx = None
            depth = 0
            for i, t in enumerate(after_then):
                if t == '(': depth += 1
                elif t == ')': depth -= 1
                elif t.upper() == 'ELSE' and depth == 0:
                    else_idx = i; break
            if else_idx is not None:
                true_part  = _join(after_then[:else_idx])
                false_part = _join(after_then[else_idx+1:])
            else:
                true_part  = after_str
                false_part = None

            if truth:
                # THEN nn — treat as GOTO
                if re.match(r'^\d+$', true_part.strip()):
                    self._exec_goto(true_part.strip())
                else:
                    self._exec(true_part.strip())
            elif false_part:
                if re.match(r'^\d+$', false_part.strip()):
                    self._exec_goto(false_part.strip())
                else:
                    self._exec(false_part.strip())
        else:
            # Multi-line IF — block form
            if not truth:
                # Skip to matching ELSE or END IF
                self._scan_forward(['ELSE', 'END IF'], nesting_open=['IF'], nesting_close=['END IF'])

    def _scan_forward(self, targets, nesting_open=None, nesting_close=None):
        """Advance self.pc until a target keyword is found at nesting level 0."""
        depth = 0
        nesting_open  = [k.upper() for k in (nesting_open  or [])]
        nesting_close = [k.upper() for k in (nesting_close or [])]
        targets_up    = [t.upper() for t in targets]

        while self.pc < len(self.program):
            _, stmt = self.program[self.pc]
            self.pc += 1
            s = stmt.strip().upper()

            # Detect leading keyword
            kw = s.split()[0] if s.split() else ''
            two = ' '.join(s.split()[:2]) if len(s.split()) >= 2 else ''

            if two in nesting_open or kw in nesting_open:
                depth += 1
                continue
            if depth > 0:
                if two in nesting_close or kw in nesting_close:
                    depth -= 1
                continue
            if two in targets_up or kw in targets_up:
                # Check if there's a statement after the keyword on the same line
                # (e.g. ELSE stmt — execute stmt)
                for tgt in targets_up:
                    if two == tgt:
                        after = stmt.strip()[len(tgt):].strip()
                        if after:
                            self._exec(after)
                        return
                    if kw == tgt and tgt not in ('END IF', 'END SELECT'):
                        after = stmt.strip()[len(tgt):].strip()
                        if after:
                            self._exec(after)
                        return
                return

    # ── FOR / NEXT ────────────────────────────────────────────────────────

    def _exec_for(self, rest):
        # FOR var = start TO limit [STEP step]
        m = re.match(r'([A-Za-z_]\w*[$%!#]?)\s*=\s*(.*?)\s+TO\s+(.*?)(?:\s+STEP\s+(.+))?$',
                     rest.strip(), re.IGNORECASE)
        if not m:
            raise BASICError(f'FOR syntax error: {rest}')
        var   = m.group(1).upper()
        start = self._eval(m.group(2))
        limit = self._eval(m.group(3))
        step  = self._eval(m.group(4)) if m.group(4) else 1

        self.vars[var] = self._coerce_num(start)
        # Check immediately
        if (step > 0 and self.vars[var] > limit) or (step < 0 and self.vars[var] < limit):
            # Skip to matching NEXT
            self._scan_to_next(var)
        else:
            self.for_stack.append({'var': var, 'limit': limit, 'step': step, 'pc': self.pc})

    def _exec_next(self, rest):
        if not self.for_stack:
            raise BASICError('NEXT without FOR')
        frame = self.for_stack[-1]
        var = rest.strip().upper() if rest.strip() else frame['var']
        # Match correct frame
        while self.for_stack and self.for_stack[-1]['var'] != var:
            self.for_stack.pop()
        if not self.for_stack:
            raise BASICError(f'NEXT {var} without matching FOR')
        frame = self.for_stack[-1]
        frame['var'] = frame['var']
        self.vars[frame['var']] += frame['step']
        if (frame['step'] > 0 and self.vars[frame['var']] <= frame['limit']) or \
           (frame['step'] < 0 and self.vars[frame['var']] >= frame['limit']) or \
           (frame['step'] == 0):
            self.pc = frame['pc']
        else:
            self.for_stack.pop()

    def _scan_to_next(self, var):
        depth = 0
        while self.pc < len(self.program):
            _, stmt = self.program[self.pc]
            self.pc += 1
            kw = stmt.strip().upper().split()[0] if stmt.strip() else ''
            if kw == 'FOR': depth += 1
            elif kw == 'NEXT':
                if depth > 0: depth -= 1
                else: break

    def _exit_for(self):
        if self.for_stack:
            self.for_stack.pop()
            self._scan_to_next('')

    # ── WHILE / WEND ──────────────────────────────────────────────────────

    def _exec_while(self, rest):
        cond = self._eval(rest.strip())
        if self._truth(cond):
            self.while_stack.append({'pc': self.pc - 1, 'cond': rest.strip()})
        else:
            self._scan_to_wend()

    def _exec_wend(self):
        if not self.while_stack:
            raise BASICError('WEND without WHILE')
        frame = self.while_stack[-1]
        cond = self._eval(frame['cond'])
        if self._truth(cond):
            self.pc = frame['pc'] + 1
        else:
            self.while_stack.pop()

    def _scan_to_wend(self):
        depth = 0
        while self.pc < len(self.program):
            _, stmt = self.program[self.pc]
            self.pc += 1
            kw = stmt.strip().upper().split()[0] if stmt.strip() else ''
            if kw == 'WHILE': depth += 1
            elif kw == 'WEND':
                if depth > 0: depth -= 1
                else: break

    def _exit_while(self):
        if self.while_stack:
            self.while_stack.pop()
        self._scan_to_wend()

    # ── DO / LOOP ─────────────────────────────────────────────────────────

    def _exec_do(self, rest):
        rest = rest.strip().upper()
        # DO [WHILE cond] or DO [UNTIL cond]
        if rest.startswith('WHILE '):
            cond = rest[6:].strip()
            cond_lower = rest.lower()[6:]
            if not self._truth(self._eval(cond)):
                self._scan_to_loop()
                return
            self.do_stack.append({'pc': self.pc - 1, 'type': 'WHILE', 'cond': cond_lower})
        elif rest.startswith('UNTIL '):
            cond = rest[6:].strip()
            cond_lower = rest.lower()[6:]
            if self._truth(self._eval(cond)):
                self._scan_to_loop()
                return
            self.do_stack.append({'pc': self.pc - 1, 'type': 'UNTIL', 'cond': cond_lower})
        else:
            self.do_stack.append({'pc': self.pc - 1, 'type': None, 'cond': None})

    def _exec_loop(self, rest):
        if not self.do_stack:
            raise BASICError('LOOP without DO')
        frame = self.do_stack[-1]
        rest = rest.strip().upper()
        if rest.startswith('WHILE '):
            cond = rest[6:]
            if self._truth(self._eval(cond)):
                self.pc = frame['pc'] + 1
            else:
                self.do_stack.pop()
        elif rest.startswith('UNTIL '):
            cond = rest[6:]
            if not self._truth(self._eval(cond)):
                self.pc = frame['pc'] + 1
            else:
                self.do_stack.pop()
        else:
            # DO...LOOP with condition at top
            if frame['type'] == 'WHILE':
                if self._truth(self._eval(frame['cond'])):
                    self.pc = frame['pc'] + 1
                else:
                    self.do_stack.pop()
            elif frame['type'] == 'UNTIL':
                if not self._truth(self._eval(frame['cond'])):
                    self.pc = frame['pc'] + 1
                else:
                    self.do_stack.pop()
            else:
                # Unconditional loop — jump back
                self.pc = frame['pc'] + 1

    def _scan_to_loop(self):
        depth = 0
        while self.pc < len(self.program):
            _, stmt = self.program[self.pc]
            self.pc += 1
            kw = stmt.strip().upper().split()[0] if stmt.strip() else ''
            if kw == 'DO': depth += 1
            elif kw == 'LOOP':
                if depth > 0: depth -= 1
                else: break

    def _exit_do(self):
        if self.do_stack:
            self.do_stack.pop()
        self._scan_to_loop()

    # ── GOTO / GOSUB / RETURN ─────────────────────────────────────────────

    def _exec_goto(self, target):
        idx = self._resolve_target(target)
        if idx is None:
            raise BASICError(f'GOTO target not found: {target}')
        self.pc = idx

    def _exec_gosub(self, target):
        idx = self._resolve_target(target)
        if idx is None:
            raise BASICError(f'GOSUB target not found: {target}')
        self.call_stack.append(self.pc)
        self.pc = idx

    def _exec_return(self):
        if not self.call_stack:
            raise BASICError('RETURN without GOSUB')
        self.pc = self.call_stack.pop()

    def _resolve_target(self, target):
        target = target.strip().upper()
        if target.isdigit():
            return self.line_map.get(int(target))
        return self.label_map.get(target)

    # ── DIM ───────────────────────────────────────────────────────────────

    def _exec_dim(self, rest):
        for decl in self._csv_split(rest):
            decl = decl.strip()
            m = re.match(r'([A-Za-z_]\w*[$%!#]?)\s*\((.+)\)', decl, re.IGNORECASE)
            if not m:
                continue
            name = m.group(1).upper()
            dims = [int(self._eval(d.strip())) for d in m.group(2).split(',')]
            self.array_dims[name] = tuple(dims)
            self.arrays[name] = {}

    # ── READ ──────────────────────────────────────────────────────────────

    def _exec_read(self, rest):
        for vname in self._csv_split(rest):
            vname = vname.strip().upper()
            if self.data_ptr >= len(self.data_values):
                raise BASICError('Out of DATA')
            val = self.data_values[self.data_ptr]
            self.data_ptr += 1
            if vname.endswith('$'):
                self.vars[vname] = str(val)
            else:
                self.vars[vname] = self._coerce_num(val)

    # ── SWAP ──────────────────────────────────────────────────────────────

    def _exec_swap(self, rest):
        parts = [p.strip().upper() for p in rest.split(',', 1)]
        if len(parts) != 2:
            raise BASICError('SWAP requires two variables')
        a, b = parts
        va = self.vars.get(a, '' if a.endswith('$') else 0)
        vb = self.vars.get(b, '' if b.endswith('$') else 0)
        self.vars[a] = vb
        self.vars[b] = va

    # ── SELECT CASE ───────────────────────────────────────────────────────

    def _exec_select(self, rest):
        rest = rest.strip()
        if rest.upper().startswith('CASE'):
            rest = rest[4:].strip()
        val = self._eval(rest)
        self.select_stack.append(val)
        # Scan to first CASE
        self._scan_forward(['CASE'], nesting_open=['SELECT CASE', 'SELECT'],
                           nesting_close=['END SELECT'])

    def _exec_case(self, rest):
        rest = rest.strip()
        if not self.select_stack:
            raise BASICError('CASE without SELECT')
        val = self.select_stack[-1]

        if rest.upper() == 'ELSE':
            return  # fall through — execute this case body

        # Check case expression(s)
        matched = False
        for item in self._csv_split(rest):
            item = item.strip()
            m_is = re.match(r'IS\s*([<>=!]+)\s*(.*)', item, re.IGNORECASE)
            m_to = re.match(r'(.+)\s+TO\s+(.+)', item, re.IGNORECASE)
            if m_is:
                op, expr = m_is.group(1), self._eval(m_is.group(2).strip())
                matched = self._expr._cmp(op.replace('!', '<>'), val, expr) != 0
            elif m_to:
                lo = self._eval(m_to.group(1).strip())
                hi = self._eval(m_to.group(2).strip())
                matched = (lo <= val <= hi)
            else:
                matched = (val == self._eval(item))
            if matched:
                break

        if not matched:
            # Skip to next CASE or END SELECT
            self._scan_forward(['CASE', 'END SELECT'],
                               nesting_open=['SELECT CASE', 'SELECT'],
                               nesting_close=['END SELECT'])

    # ── Helpers ────────────────────────────────────────────────────────────

    def _eval(self, expr_str):
        if not expr_str:
            return 0
        tokens = _tokenise(expr_str.strip())
        if not tokens:
            return 0
        return self._expr.eval(tokens)

    def _truth(self, v):
        try: return float(v) != 0
        except (TypeError, ValueError): return bool(v)

    def _split_kw(self, stmt):
        """Return (KEYWORD, rest) for the first word of stmt."""
        m = re.match(r'^([A-Za-z_]\w*)(.*)$', stmt.strip())
        if not m:
            return '', stmt
        kw = m.group(1).upper()
        rest = m.group(2).strip()
        # Handle two-word keywords: END IF, END SELECT, LINE INPUT
        two_word = kw + ' ' + (rest.split()[0].upper() if rest.split() else '')
        if two_word in ('END IF', 'END SELECT', 'LINE INPUT'):
            kw2 = two_word
            rest2 = rest[len(rest.split()[0]):].strip() if rest.split() else ''
            return kw2, rest2
        return kw, rest

    def _strip_comment(self, stmt):
        """Remove trailing REM or ' comment, respecting strings."""
        result, in_str = [], False
        i = 0
        while i < len(stmt):
            c = stmt[i]
            if c == '"':
                in_str = not in_str
                result.append(c)
            elif not in_str and c == "'":
                break
            elif not in_str and stmt[i:i+3].upper() == 'REM' and (i == 0 or not stmt[i-1:i].isalnum()):
                break
            else:
                result.append(c)
            i += 1
        return ''.join(result).rstrip()

    def _colon_split(self, stmt):
        """Split on colons not inside strings or after line numbers."""
        parts, cur, in_str = [], [], False
        for ch in stmt:
            if ch == '"': in_str = not in_str
            if ch == ':' and not in_str:
                parts.append(''.join(cur)); cur = []
            else:
                cur.append(ch)
        parts.append(''.join(cur))
        return [p for p in parts if p.strip()]

    def _csv_split(self, s):
        parts, cur, depth, in_str = [], [], 0, False
        for ch in s:
            if ch == '"': in_str = not in_str
            if not in_str:
                if ch == '(': depth += 1
                elif ch == ')': depth -= 1
                elif ch == ',' and depth == 0:
                    parts.append(''.join(cur)); cur = []; continue
            cur.append(ch)
        parts.append(''.join(cur))
        return parts
