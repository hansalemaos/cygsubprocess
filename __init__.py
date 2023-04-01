import os
import subprocess
import sys
import tempfile
import threading
from functools import partial


def touch(path: str) -> bool:
    # touch('f:\\dada\\baba\\caca\\myfile.html')
    # original: https://github.com/andrewp-as-is/touch.py (not working anymore)
    def _fullpath(path):
        return os.path.abspath(os.path.expanduser(path))

    def _mkdir(path):
        path = path.replace("\\", "/")
        if path.find("/") > 0 and not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

    def _utime(path):
        try:
            os.utime(path, None)
        except Exception:
            open(path, "a").close()

    def touch_(path):
        if path:
            path = _fullpath(path)
            _mkdir(path)
            _utime(path)

    try:
        touch_(path)
        return True
    except Exception as Fe:
        print(Fe)
        return False


def callback_func(pid):
    Popen(f"taskkill /F /PID {pid} /T")


def timer_thread(timer, pid):
    timer.start()
    timer.join()
    callback_func(pid)


def cyg2winpath(cyg_path, path):
    path = os.path.normpath(path)
    return subprocess.check_output([cyg_path, "-w", path]).strip(b"\n").decode()


def win2cgypath(cyg_path, path):
    path = os.path.normpath(path)
    return subprocess.check_output([cyg_path, "-p", path]).strip(b"\n").decode()


def get_tmpfile(suffix=".bin"):
    tfp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    filename = tfp.name
    filename = os.path.normpath(filename)
    tfp.close()
    touch(filename)
    return filename


class Popen(subprocess.Popen):
    def __init__(
        self,
        args,
        bufsize=-1,
        executable=None,
        stdin=None,
        stdout=None,
        stderr=None,
        preexec_fn=None,
        close_fds=True,
        shell=False,
        cwd=None,
        env=None,
        universal_newlines=None,
        startupinfo=None,
        creationflags=0,
        restore_signals=True,
        start_new_session=False,
        pass_fds=(),
        *,
        group=None,
        extra_groups=None,
        user=None,
        umask=-1,
        encoding=None,
        errors=None,
        text=None,
        pipesize=-1,
        process_group=None,
        print_output=True,
        **kwargs,
    ):
        stdin = subprocess.PIPE
        stdout = subprocess.PIPE
        universal_newlines = False
        stderr = subprocess.PIPE
        # shell = False
        startupinfo = subprocess.STARTUPINFO()
        creationflags = 0 | subprocess.CREATE_NO_WINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        hastimeout = "timeout" in kwargs
        timeout = 0
        if hastimeout:
            timeout = kwargs["timeout"]

            del kwargs["timeout"]

        super().__init__(
            args,
            bufsize=bufsize,
            executable=executable,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            preexec_fn=preexec_fn,
            close_fds=close_fds,
            shell=shell,
            cwd=cwd,
            env=env,
            universal_newlines=universal_newlines,
            startupinfo=startupinfo,
            creationflags=creationflags,
            restore_signals=restore_signals,
            start_new_session=start_new_session,
            pass_fds=pass_fds,
            group=group,
            extra_groups=extra_groups,
            user=user,
            umask=umask,
            encoding=encoding,
            errors=errors,
            text=text,
            **kwargs,
        )
        if hastimeout:
            timer = threading.Timer(timeout, partial(callback_func, self.pid))
            timer.start()
        self.stdout_lines = []
        self.stderr_lines = []
        self._stdout_reader = StreamReader(self.stdout, self.stdout_lines)
        self._stderr_reader = StreamReader(self.stderr, self.stderr_lines)
        stdo = self._stdout_reader.start()
        stdee = self._stderr_reader.start()
        for stdo_ in stdo:
            self.stdout_lines.append(stdo_)
            if print_output:
                print(stdo_)
        for stde_ in stdee:
            self.stderr_lines.append(stde_)
            if print_output:
                print(stde_)

        if hastimeout:
            timer.cancel()
        self.stdout = b"".join(self.stdout_lines)
        self.stderr = b"".join(self.stderr_lines)

    def __exit__(self, *args, **kwargs):
        try:
            self._stdout_reader.stop()
            self._stderr_reader.stop()
        except Exception as fe:
            pass

        super().__exit__(*args, **kwargs)

    def __del__(self, *args, **kwargs):
        try:
            self._stdout_reader.stop()
            self._stderr_reader.stop()
        except Exception as fe:
            pass
        super().__del__(*args, **kwargs)


class StreamReader:
    def __init__(self, stream, lines):
        self._stream = stream
        self._lines = lines
        self._stopped = False

    def start(self):
        while not self._stopped:
            line = self._stream.readline()
            if not line:
                break
            yield line

    def stop(self):
        self._stopped = True


class Bashsubprocess:
    def __init__(self, bash_exe, cgypath_exe=None):
        self.bash_exe = os.path.normpath(bash_exe)
        self.folder = os.path.normpath(os.path.basename(self.bash_exe))
        if sys.path[0] != self.folder:
            sys.path.insert(0, self.folder)
        self._cmdadd = [self.bash_exe, "-c"]
        self.cgypath_exe = os.path.normpath(cgypath_exe)

    def execute_print_capture(self, cmd):
        if not isinstance(cmd, list):
            cmd = [cmd]
        wholcmd = self._cmdadd + cmd
        p = Popen(wholcmd)
        return p

    def execute_capture(self, cmd):
        if not isinstance(cmd, list):
            cmd = [cmd]
        wholcmd = self._cmdadd + cmd
        p = Popen(wholcmd, print_output=False)
        return p

    def convert_path_cyg2win(self, path):
        return cyg2winpath(self.cgypath_exe, path)

    def convert_path_win2cyg(self, path):
        return win2cgypath(self.cgypath_exe, path)

    def exec_sh_to_file(self, bashscr, printoutput=True):
        btmp = get_tmpfile(suffix=".sh")

        with open(btmp, mode="w", encoding="utf-8", newline="\n") as f:
            f.write(bashscr)

        cpa = self.convert_path_win2cyg(btmp)
        co = [f"chmod +x {cpa}", cpa]
        if printoutput:
            cmd3 = self.execute_print_capture(co[0])
            cmd3 = self.execute_print_capture(co[1])
        else:
            cmd3 = self.execute_capture(co[0])
            cmd3 = self.execute_capture(co[1])
        return cmd3

    def exec_sh_directly(self, bashscr, printoutput=True):
        if printoutput:
            cmd3 = self.execute_print_capture(bashscr)
        else:
            cmd3 = self.execute_capture(bashscr)
        return cmd3


