// Windows 3.11 Desktop Engine

const Desktop = {
    zCounter: 100,
    windows: {},
    activeWindow: null,
    _resizeState: null,   // shared resize state across all windows
    _dragState: null,     // shared drag state

    init() {
        this.setupDesktopIcons();
        this.setupGlobalEvents();
        // Open Program Manager on load
        setTimeout(() => this.openWindow('program-manager'), 100);
    },

    // ===== GLOBAL EVENTS =====
    setupGlobalEvents() {
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.menu-item')) {
                document.querySelectorAll('.dropdown-menu.visible').forEach(m => {
                    m.classList.remove('visible');
                    m.previousElementSibling?.classList.remove('active');
                });
            }
        });

        // ── Shared drag handler ──────────────────────────────────────────────
        document.addEventListener('mousemove', (e) => {
            const d = this._dragState;
            if (d) {
                const dx = e.clientX - d.startX;
                const dy = e.clientY - d.startY;
                d.win.style.left = Math.max(0, d.origLeft + dx) + 'px';
                d.win.style.top  = Math.max(0, d.origTop  + dy) + 'px';
            }

            // ── Shared resize handler ────────────────────────────────────────
            const s = this._resizeState;
            if (s) {
                const dx = e.clientX - s.startX;
                const dy = e.clientY - s.startY;
                const MIN_W = 200, MIN_H = 80;
                let { origLeft: left, origTop: top, origW: w, origH: h } = s;

                if (s.dir.includes('e')) w = Math.max(MIN_W, w + dx);
                if (s.dir.includes('s')) h = Math.max(MIN_H, h + dy);
                if (s.dir.includes('w')) {
                    const nw = Math.max(MIN_W, w - dx);
                    left += w - nw; w = nw;
                }
                if (s.dir.includes('n')) {
                    const nh = Math.max(MIN_H, h - dy);
                    top += h - nh; h = nh;
                }

                s.win.style.left   = Math.max(0, left) + 'px';
                s.win.style.top    = Math.max(0, top)  + 'px';
                s.win.style.width  = w + 'px';
                s.win.style.height = h + 'px';
            }
        });

        document.addEventListener('mouseup', () => {
            this._dragState   = null;
            this._resizeState = null;
            document.body.style.cursor = '';
        });
    },

    // ===== DESKTOP ICONS =====
    setupDesktopIcons() {
        document.querySelectorAll('.desktop-icon').forEach(icon => {
            let clickCount = 0, clickTimer = null;

            icon.addEventListener('click', (e) => {
                // Deselect all
                document.querySelectorAll('.desktop-icon.selected').forEach(i => i.classList.remove('selected'));
                icon.classList.add('selected');
                e.stopPropagation();

                clickCount++;
                if (clickCount === 1) {
                    clickTimer = setTimeout(() => { clickCount = 0; }, 400);
                } else if (clickCount === 2) {
                    clearTimeout(clickTimer);
                    clickCount = 0;
                    const target = icon.dataset.opens;
                    if (target) this.openWindow(target);
                }
            });
        });

        document.getElementById('desktop').addEventListener('click', () => {
            document.querySelectorAll('.desktop-icon.selected').forEach(i => i.classList.remove('selected'));
        });
    },

    // ===== WINDOW MANAGEMENT =====
    openWindow(id) {
        const win = document.getElementById(id);
        if (!win) return;

        if (win.classList.contains('minimized')) {
            win.classList.remove('minimized');
        }

        if (!this.windows[id]) {
            this.windows[id] = { minimized: false, maximized: false };
            this.initDragging(win);
            this.initResizing(win);
        }

        this.focusWindow(win);
    },

    focusWindow(win) {
        document.querySelectorAll('.win-window.focused').forEach(w => w.classList.remove('focused'));
        win.classList.add('focused');
        win.style.zIndex = ++this.zCounter;
        this.activeWindow = win;
    },

    closeWindow(id) {
        const win = document.getElementById(id);
        if (!win) return;
        win.classList.add('minimized');
        delete this.windows[id];
        win.classList.remove('maximized');
        win.style.width = '';
        win.style.height = '';
    },

    minimizeWindow(id) {
        const win = document.getElementById(id);
        if (!win) return;
        win.classList.add('minimized');
        if (this.windows[id]) this.windows[id].minimized = true;
    },

    maximizeWindow(id) {
        const win = document.getElementById(id);
        if (!win) return;
        const data = this.windows[id];
        if (!data) return;

        if (data.maximized) {
            win.classList.remove('maximized');
            win.style.top = data.prevTop || '50px';
            win.style.left = data.prevLeft || '50px';
            win.style.width = data.prevWidth || '400px';
            win.style.height = data.prevHeight || '300px';
            data.maximized = false;
        } else {
            data.prevTop = win.style.top;
            data.prevLeft = win.style.left;
            data.prevWidth = win.style.width;
            data.prevHeight = win.style.height;
            win.classList.add('maximized');
            data.maximized = true;
        }
    },

    // ===== DRAGGING =====
    initDragging(win) {
        const titleBar = win.querySelector('.title-bar');

        titleBar.addEventListener('mousedown', (e) => {
            if (e.target.classList.contains('title-btn')) return;
            if (this.windows[win.id]?.maximized) return;
            this._dragState = {
                win, startX: e.clientX, startY: e.clientY,
                origLeft: win.offsetLeft, origTop: win.offsetTop
            };
            this.focusWindow(win);
            e.preventDefault();
        });

        titleBar.addEventListener('dblclick', (e) => {
            if (e.target.classList.contains('title-btn')) return;
            this.maximizeWindow(win.id);
        });

        win.addEventListener('mousedown', () => this.focusWindow(win));
    },

    // ===== RESIZING (8 directions) =====
    initResizing(win) {
        // Remove old single-corner handle; inject 8 directional handles
        win.querySelectorAll('.resize-handle, .rh').forEach(h => h.remove());

        const DIRS = ['n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw'];
        DIRS.forEach(dir => {
            const h = document.createElement('div');
            h.className = `rh rh-${dir}`;
            win.appendChild(h);

            h.addEventListener('mousedown', (e) => {
                if (this.windows[win.id]?.maximized) return;
                this._resizeState = {
                    win, dir,
                    startX: e.clientX, startY: e.clientY,
                    origLeft: win.offsetLeft, origTop: win.offsetTop,
                    origW: win.offsetWidth,   origH: win.offsetHeight
                };
                e.preventDefault();
                e.stopPropagation();
            });
        });
    },

    // ===== MENUS =====
    toggleMenu(menuId, triggerEl) {
        const menu = document.getElementById(menuId);
        const wasVisible = menu.classList.contains('visible');

        // Close all menus
        document.querySelectorAll('.dropdown-menu.visible').forEach(m => {
            m.classList.remove('visible');
            m.previousElementSibling?.classList.remove('active');
        });

        if (!wasVisible) {
            const rect = triggerEl.getBoundingClientRect();
            menu.style.top = rect.bottom + 'px';
            menu.style.left = rect.left + 'px';
            menu.classList.add('visible');
            triggerEl.classList.add('active');
        }
    }
};

// ===== CALCULATOR LOGIC =====
const Calculator = {
    display: '',
    operand1: null,
    operator: null,
    waitingForOperand: false,

    init() {
        this.updateDisplay('0');
    },

    press(val) {
        if (val === 'C') {
            this.display = '';
            this.operand1 = null;
            this.operator = null;
            this.waitingForOperand = false;
            this.updateDisplay('0');
            return;
        }
        if (val === 'CE') {
            this.display = '';
            this.updateDisplay('0');
            return;
        }
        if (val === '+/-') {
            const cur = parseFloat(this.display || '0');
            this.display = String(-cur);
            this.updateDisplay(this.display);
            return;
        }
        if (['+', '-', '*', '/'].includes(val)) {
            if (this.operator && !this.waitingForOperand) {
                this.calculate();
            }
            this.operand1 = parseFloat(this.display || '0');
            this.operator = val;
            this.waitingForOperand = true;
            return;
        }
        if (val === '=') {
            this.calculate();
            this.operator = null;
            this.waitingForOperand = false;
            return;
        }
        if (val === '.') {
            if (this.waitingForOperand) { this.display = '0.'; this.waitingForOperand = false; }
            else if (!this.display.includes('.')) this.display += '.';
            this.updateDisplay(this.display);
            return;
        }
        if (val === '%') {
            const cur = parseFloat(this.display || '0');
            this.display = String(cur / 100);
            this.updateDisplay(this.display);
            return;
        }
        if (val === '1/x') {
            const cur = parseFloat(this.display || '1');
            this.display = String(1 / cur);
            this.updateDisplay(this.display);
            return;
        }

        // Digit
        if (this.waitingForOperand) {
            this.display = val;
            this.waitingForOperand = false;
        } else {
            this.display = this.display === '0' ? val : this.display + val;
        }
        this.updateDisplay(this.display);
    },

    calculate() {
        if (this.operator === null || this.operand1 === null) return;
        const op2 = parseFloat(this.display || '0');
        let result;
        switch (this.operator) {
            case '+': result = this.operand1 + op2; break;
            case '-': result = this.operand1 - op2; break;
            case '*': result = this.operand1 * op2; break;
            case '/': result = op2 === 0 ? 'Error' : this.operand1 / op2; break;
        }
        this.display = String(result);
        this.updateDisplay(this.display);
        this.operand1 = result;
    },

    updateDisplay(val) {
        const el = document.getElementById('calc-display');
        if (el) {
            const str = String(val);
            el.textContent = str.length > 12 ? parseFloat(str).toExponential(6) : str;
        }
    }
};

// ===== INIT =====
window.addEventListener('DOMContentLoaded', () => {
    Desktop.init();
    Calculator.init();
});
