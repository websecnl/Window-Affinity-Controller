"""Window Affinity Controller. Windows 10 2004+, x64 Python and x64 targets."""
import sys
if sys.platform != 'win32':
    raise SystemExit('This application requires Windows.')
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

if C.sizeof(C.c_void_p) != 8 or sys.getwindowsversion().build < 19041:
    raise SystemExit('Use x64 Python on Windows 10 version 2004 or newer.')

K = C.WinDLL('kernel32', use_last_error=True)
U = C.WinDLL('user32', use_last_error=True)
PTR, SIZE, DWORD = C.c_void_p, C.c_size_t, W.DWORD
CALLBACK = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)


def bind(dll, name, args, result):
    f = getattr(dll, name)
    f.argtypes, f.restype = args, result
    return f


OpenProcess = bind(K, 'OpenProcess', [DWORD, W.BOOL, DWORD], W.HANDLE)
CloseHandle = bind(K, 'CloseHandle', [W.HANDLE], W.BOOL)
Wait = bind(K, 'WaitForSingleObject', [W.HANDLE, DWORD], DWORD)
Alloc = bind(K, 'VirtualAllocEx', [W.HANDLE, PTR, SIZE, DWORD, DWORD], PTR)
Free = bind(K, 'VirtualFreeEx', [W.HANDLE, PTR, SIZE, DWORD], W.BOOL)
Write = bind(K, 'WriteProcessMemory', [W.HANDLE, PTR, PTR, SIZE, C.POINTER(SIZE)], W.BOOL)
Read = bind(K, 'ReadProcessMemory', [W.HANDLE, PTR, PTR, SIZE, C.POINTER(SIZE)], W.BOOL)
RemoteThread = bind(K, 'CreateRemoteThread', [W.HANDLE, PTR, SIZE, PTR, PTR, DWORD, C.POINTER(DWORD)], W.HANDLE)
ExitCode = bind(K, 'GetExitCodeThread', [W.HANDLE, C.POINTER(DWORD)], W.BOOL)
IsWow64Process2 = bind(K, 'IsWow64Process2', [W.HANDLE, C.POINTER(W.WORD), C.POINTER(W.WORD)], W.BOOL)
GetTimes = bind(K, 'GetProcessTimes', [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4, W.BOOL)
QueryName = bind(K, 'QueryFullProcessImageNameW', [W.HANDLE, DWORD, W.LPWSTR, C.POINTER(DWORD)], W.BOOL)
Snapshot = bind(K, 'CreateToolhelp32Snapshot', [DWORD, DWORD], W.HANDLE)
ModuleHandleEx = bind(K, 'GetModuleHandleExW', [DWORD, PTR, C.POINTER(W.HMODULE)], W.BOOL)
ModuleName = bind(K, 'GetModuleFileNameW', [W.HMODULE, W.LPWSTR, DWORD], DWORD)
EnumWindows = bind(U, 'EnumWindows', [CALLBACK, W.LPARAM], W.BOOL)
WindowPID = bind(U, 'GetWindowThreadProcessId', [W.HWND, C.POINTER(DWORD)], DWORD)
TextLength = bind(U, 'GetWindowTextLengthW', [W.HWND], C.c_int)
WindowText = bind(U, 'GetWindowTextW', [W.HWND, W.LPWSTR, C.c_int], C.c_int)
Visible = bind(U, 'IsWindowVisible', [W.HWND], W.BOOL)
Affinity = bind(U, 'GetWindowDisplayAffinity', [W.HWND, C.POINTER(DWORD)], W.BOOL)
LoadLibraryW = bind(K, 'LoadLibraryW', [W.LPCWSTR], W.HMODULE)


class Module(C.Structure):
    _fields_ = [('dwSize', DWORD), ('th32ModuleID', DWORD), ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD), ('ProccntUsage', DWORD), ('modBaseAddr', PTR),
                ('modBaseSize', DWORD), ('hModule', W.HMODULE),
                ('szModule', W.WCHAR * 256), ('szExePath', W.WCHAR * 260)]


FirstModule = bind(K, 'Module32FirstW', [W.HANDLE, C.POINTER(Module)], W.BOOL)
NextModule = bind(K, 'Module32NextW', [W.HANDLE, C.POINTER(Module)], W.BOOL)


class Result(C.Structure):
    _fields_ = [('hwnd', C.c_uint64)] + [(n, C.c_uint32) for n in
                  ('tid', 'ok', 'error', 'observed', 'query_error', 'reserved')]


class Request(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('magic', 'affinity', 'count', 'overflow')] + [
        ('only_hwnd', C.c_uint64), ('results', Result * 2048)]


assert C.sizeof(Result) == 32 and C.sizeof(Request) == 65560


def check(value):
    if not value:
        raise C.WinError(C.get_last_error())
    return value


def created(handle):
    times = [W.FILETIME() for _ in range(4)]
    check(GetTimes(handle, *(C.byref(t) for t in times)))
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def process_info(pid):
    h = OpenProcess(0x1000, False, pid)
    if not h:
        return '<inaccessible>', None
    try:
        buf, length = C.create_unicode_buffer(32768), DWORD(32768)
        check(QueryName(h, 0, buf, C.byref(length)))
        return os.path.basename(buf.value), created(h)
    except OSError:
        return '<inaccessible>', None
    finally:
        CloseHandle(h)


def windows():
    rows, processes = [], {}

    @CALLBACK
    def collect(hwnd, unused):
        pid = DWORD()
        tid = WindowPID(hwnd, C.byref(pid))
        if not pid.value:
            return True
        if pid.value not in processes:
            processes[pid.value] = process_info(pid.value)
        name, birth = processes[pid.value]
        buf = C.create_unicode_buffer(max(1, TextLength(hwnd) + 1))
        WindowText(hwnd, buf, len(buf))
        value = DWORD()
        affinity = f'0x{value.value:X}' if Affinity(hwnd, C.byref(value)) else '?'
        rows.append(dict(hwnd=int(hwnd), pid=pid.value, tid=tid, name=name,
                         birth=birth, title=buf.value or '<untitled>',
                         visible=bool(Visible(hwnd)), affinity=affinity))
        return True

    check(EnumWindows(collect, 0))
    return rows


def modules(pid):
    # ERROR_BAD_LENGTH is a documented transient snapshot failure.
    for _ in range(8):
        h = Snapshot(0x8 | 0x10, pid)
        if h != C.c_void_p(-1).value:
            break
        if C.get_last_error() != 24:
            raise C.WinError(C.get_last_error())
    else:
        raise RuntimeError('Module snapshot repeatedly changed; try again.')
    try:
        item = Module()
        item.dwSize = C.sizeof(item)
        if not FirstModule(h, C.byref(item)):
            raise C.WinError(C.get_last_error())
        out = []
        while True:
            out.append((item.szExePath, item.szModule, int(item.modBaseAddr)))
            if not NextModule(h, C.byref(item)):
                if C.get_last_error() != 18:
                    raise C.WinError(C.get_last_error())
                return out
    finally:
        CloseHandle(h)


def remote_system_function(pid, function):
    # Resolve the actual local owner of a forwarded export, then its remote base.
    address = C.cast(function, PTR).value
    owner = W.HMODULE()
    check(ModuleHandleEx(0x4 | 0x2, PTR(address), C.byref(owner)))
    name = C.create_unicode_buffer(32768)
    check(ModuleName(owner, name, len(name)))
    basename = os.path.basename(name.value).casefold()
    for path, module, base in modules(pid):
        if module.casefold() == basename:
            return base + address - owner.value
    raise RuntimeError(f'Target does not have {basename} loaded.')


class Session:
    def __init__(self, pid, birth):
        self.pid, self.handle, self.poisoned = pid, None, False
        self.handle = check(OpenProcess(0x100000 | 0x43A, False, pid))
        try:
            if created(self.handle) != birth:
                raise RuntimeError('Process identity changed. Refresh and select again.')
            machine, native = W.WORD(), W.WORD()
            check(IsWow64Process2(self.handle, C.byref(machine), C.byref(native)))
            if machine.value != 0 or native.value != 0x8664:
                raise RuntimeError('Only native x64 targets are supported in this build.')
            self.path = Path(__file__).with_name('affinity_helper.dll').resolve()
            if not self.path.is_file():
                raise RuntimeError('Build affinity_helper.dll first using build_helper.cmd.')
            self.local = C.WinDLL(str(self.path), use_last_error=True)
            self.offset = C.cast(self.local.ApplyAffinity, PTR).value - self.local._handle
            self.base = self.find_helper()
            if not self.base:
                raw = (str(self.path) + '\0').encode('utf-16-le')
                self.invoke(remote_system_function(pid, LoadLibraryW), raw)
                self.base = self.find_helper()
                if not self.base:
                    raise RuntimeError('Target failed to load helper. Check privileges and DLL policies.')
        except Exception:
            self.close()
            raise

    def find_helper(self):
        wanted = os.path.normcase(str(self.path))
        for path, module, base in modules(self.pid):
            if os.path.normcase(path) == wanted:
                return base
        return None

    def invoke(self, address, raw, readback=False):
        if self.poisoned:
            raise RuntimeError('Previous call timed out; restart the target before retrying.')
        if Wait(self.handle, 0) != 258:
            raise RuntimeError('Target process exited. Refresh and select again.')
        memory = check(Alloc(self.handle, None, len(raw), 0x3000, 0x04))
        thread, safe_free = None, True
        try:
            buf, amount = C.create_string_buffer(raw), SIZE()
            check(Write(self.handle, memory, buf, len(raw), C.byref(amount)))
            if amount.value != len(raw):
                raise RuntimeError('Incomplete remote write.')
            thread = check(RemoteThread(self.handle, None, 0, address, memory, 0, None))
            safe_free = False
            status = Wait(thread, 10000)
            if status != 0:
                self.poisoned = True
                raise TimeoutError('Remote call did not finish within 10 seconds. Continue stopped. '
                                   'Its buffer was retained to avoid freeing live memory; restart target.')
            safe_free = True
            code = DWORD()
            check(ExitCode(thread, C.byref(code)))
            if readback:
                if code.value:
                    raise RuntimeError(f'Helper returned error {code.value}.')
                check(Read(self.handle, memory, buf, len(raw), C.byref(amount)))
                if amount.value != len(raw):
                    raise RuntimeError('Incomplete remote read.')
                return bytes(buf.raw[:len(raw)])
            return code.value
        finally:
            if thread:
                CloseHandle(thread)
            if safe_free:
                Free(self.handle, memory, 0, 0x8000)

    def apply(self, affinity, hwnd):
        if Wait(self.handle, 0) != 258:
            raise RuntimeError('Target exited. Refresh and select again.')
        if self.find_helper() != self.base:
            raise RuntimeError('Helper module changed or unloaded; restart target.')
        request = Request()
        request.magic, request.affinity, request.only_hwnd = 0x57414631, affinity, hwnd
        response = Request.from_buffer_copy(self.invoke(self.base + self.offset, bytes(request), True))
        if response.count > 2048:
            raise RuntimeError('Invalid response size.')
        lines = []
        for r in response.results[:response.count]:
            observed = f'0x{r.observed:X}' if not r.query_error else f'unknown (query error {r.query_error})'
            outcome = 'OK' if r.ok else f'FAILED {r.error}: {C.FormatError(r.error).strip()}'
            lines.append(f'PID {self.pid} TID {r.tid} HWND 0x{r.hwnd:X}: {outcome}; readback {observed}')
        if response.overflow:
            raise RuntimeError('More than 2048 windows matched; result capacity exceeded.')
        if not lines:
            lines.append(f'PID {self.pid}: no matching top-level windows currently exist.')
        return lines

    def close(self):
        if self.handle:
            CloseHandle(self.handle)
            self.handle = None


class Worker(threading.Thread):
    def __init__(self, output):
        super().__init__(daemon=True)
        self.jobs, self.output = queue.Queue(), output

    def run(self):
        sessions = {}
        blocked = set()
        try:
            while True:
                job = self.jobs.get()
                if job is None:
                    return
                try:
                    kind, payload = job
                    if kind == 'refresh':
                        self.output.put(('rows', windows()))
                    else:
                        targets, affinity = payload
                        lines = []
                        for pid, birth, hwnd in targets:
                            key = (pid, birth)
                            if key in blocked:
                                raise RuntimeError('A call timed out in this target. Restart target before retrying.')
                            try:
                                if key not in sessions:
                                    sessions[key] = Session(pid, birth)
                                lines.extend(sessions[key].apply(affinity, hwnd))
                            except TimeoutError:
                                blocked.add(key)
                                raise
                        self.output.put(('result', lines))
                except Exception as e:
                    self.output.put(('error', str(e)))
                finally:
                    self.output.put(('done', None))
        finally:
            for s in sessions.values():
                s.close()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Window Affinity Controller')
        self.geometry('1120x720')
        self.rows, self.by_id, self.busy, self.active = [], {}, False, None
        self.last_result = None
        self.output = queue.Queue()
        self.worker = Worker(self.output)
        self.worker.start()
        self.filter = tk.StringVar()
        self.scope = tk.StringVar(value='process')
        self.continue_var = tk.BooleanVar(value=False)
        self.hidden = tk.BooleanVar(value=False)
        self.interval = tk.StringVar(value='1000')
        top = ttk.Frame(self, padding=10)
        top.pack(fill='x')
        ttk.Label(top, text='Filter by process name, PID, HWND, or title:').pack(side='left')
        ttk.Entry(top, textvariable=self.filter, width=40).pack(side='left', padx=8)
        ttk.Button(top, text='Refresh', command=self.refresh).pack(side='left')
        ttk.Checkbutton(top, text='Show hidden / untitled', variable=self.hidden,
                        command=self.render).pack(side='left', padx=8)
        self.filter.trace_add('write', lambda *_: self.render())
        frame = ttk.Frame(self, padding=(10, 0))
        frame.pack(fill='both', expand=True)
        cols = ('name', 'pid', 'tid', 'hwnd', 'affinity', 'title')
        self.tree = ttk.Treeview(frame, columns=cols, show='headings', selectmode='extended')
        for name, width in zip(cols, (165, 70, 70, 130, 65, 400)):
            self.tree.heading(name, text=name.upper())
            self.tree.column(name, width=width)
        scroll = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        bar = ttk.Frame(self, padding=10)
        bar.pack(fill='x')
        ttk.Radiobutton(bar, text='All windows in selected PID(s), all threads',
                        variable=self.scope, value='process').pack(side='left')
        ttk.Radiobutton(bar, text='Selected HWND(s) only', variable=self.scope,
                        value='window').pack(side='left', padx=10)
        ttk.Button(bar, text='Protect', command=lambda: self.apply(0x11)).pack(side='left', padx=5)
        ttk.Button(bar, text='Unprotect', command=lambda: self.apply(0)).pack(side='left', padx=5)
        lower = ttk.Frame(self, padding=(10, 0, 10, 10))
        lower.pack(fill='x')
        ttk.Checkbutton(lower, text='Continue', variable=self.continue_var,
                        command=self.toggle_continue).pack(side='left')
        ttk.Label(lower, text='Interval (ms, minimum 250):').pack(side='left', padx=10)
        ttk.Entry(lower, textvariable=self.interval, width=8).pack(side='left')
        ttk.Button(lower, text='Stop', command=self.stop).pack(side='left', padx=10)
        self.status = tk.StringVar(value='Ready')
        ttk.Label(lower, textvariable=self.status).pack(side='left', padx=10)
        self.log = tk.Text(self, height=12, wrap='word', state='disabled')
        self.log.pack(fill='x', padx=10, pady=(0, 10))
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.after(100, self.poll)
        self.refresh()

    def append(self, text):
        self.log.configure(state='normal')
        self.log.insert('end', text + '\n')
        if int(self.log.index('end-1c').split('.')[0]) > 1500:
            self.log.delete('1.0', '500.0')
        self.log.see('end')
        self.log.configure(state='disabled')

    def dispatch(self, kind, payload=None):
        self.busy = True
        self.worker.jobs.put((kind, payload))

    def refresh(self):
        if not self.busy:
            self.dispatch('refresh')

    def render(self):
        selected = {self.by_id[i]['hwnd'] for i in self.tree.selection() if i in self.by_id}
        self.tree.delete(*self.tree.get_children())
        self.by_id = {}
        term = self.filter.get().casefold().strip()
        for row in self.rows:
            if not self.hidden.get() and (not row['visible'] or row['title'] == '<untitled>'):
                continue
            values = (row['name'], row['pid'], row['tid'], f"0x{row['hwnd']:X}",
                      row['affinity'], row['title'])
            if term and not any(term in str(v).casefold() for v in values):
                continue
            key = self.tree.insert('', 'end', values=values)
            self.by_id[key] = row
            if row['hwnd'] in selected:
                self.tree.selection_add(key)

    def apply(self, affinity):
        if self.busy:
            self.append('An operation is running. Wait for it to complete before changing mode.')
            return
        rows = [self.by_id[i] for i in self.tree.selection()]
        if not rows:
            messagebox.showinfo('Select a target', 'Select one or more window rows first.')
            return
        if any(r['birth'] is None for r in rows):
            messagebox.showerror('Unavailable process', 'Cannot verify process identity for this selection.')
            return
        if self.scope.get() == 'process':
            targets = sorted({(r['pid'], r['birth'], 0) for r in rows})
        else:
            targets = sorted({(r['pid'], r['birth'], r['hwnd']) for r in rows})
        self.active = (targets, affinity)
        self.last_result = None
        self.append(('Protect' if affinity else 'Unprotect') + f': {len(targets)} target(s).')
        self.status.set('Applying...')
        self.dispatch('apply', self.active)

    def stop(self):
        self.continue_var.set(False)
        self.active = None
        self.status.set('Stopped; existing affinity is unchanged')

    def toggle_continue(self):
        if self.continue_var.get() and self.active is None:
            self.status.set('Select targets and click Protect or Unprotect')
        elif not self.continue_var.get():
            self.status.set('Continue off; existing affinity is unchanged')

    def poll(self):
        finished = False
        try:
            while True:
                kind, payload = self.output.get_nowait()
                if kind == 'rows':
                    self.rows = payload
                    self.render()
                elif kind == 'result':
                    if payload != self.last_result:
                        self.append('\n'.join(payload))
                        self.last_result = payload
                    if self.active is not None:
                        self.status.set('Applied; Continue on' if self.continue_var.get() else 'Applied once')
                elif kind == 'error':
                    self.stop()
                    self.append('ERROR: ' + payload)
                    self.status.set('Error; Continue stopped')
                elif kind == 'done':
                    self.busy = False
                    finished = True
        except queue.Empty:
            pass
        if finished:
            try:
                interval = max(250, min(60000, int(self.interval.get())))
            except ValueError:
                interval = 1000
            self.next_run = time.monotonic() + interval / 1000
        if (not self.busy and self.active and self.continue_var.get()
                and time.monotonic() >= getattr(self, 'next_run', 0)):
            self.dispatch('apply', self.active)
        self.after(100, self.poll)

    def close(self):
        self.stop()
        self.worker.jobs.put(None)
        self.destroy()


if __name__ == '__main__':
    App().mainloop()
