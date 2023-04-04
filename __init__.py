import os
import sys
import tempfile
import threading
from functools import partial
import random
from time import sleep

import requests
import pathlib
from collections import namedtuple
from add2winpath import add_to_path_all_users, add_to_path_current_user

import subprocess
import os.path

# https://www.cygwin.com/mirrors.html
mirrorpages = [
    "https://mirror.easyname.at/cygwin/",
    "https://mirror.aarnet.edu.au/pub/sourceware/cygwin/",
    "https://mirror.datacenter.by/pub/mirrors/cygwin/",
    "https://muug.ca/mirror/cygwin/",
    "https://mirror.cpsc.ucalgary.ca/mirror/cygwin.com/",
    "https://mirror.csclub.uwaterloo.ca/cygwin/",
    "https://mirrors.neusoft.edu.cn/cygwin/",
    "https://mirrors.sjtug.sjtu.edu.cn/cygwin/",
    "https://mirrors.ustc.edu.cn/cygwin/",
    "https://mirrors.zju.edu.cn/cygwin/",
    "https://mirrors.163.com/cygwin/",
    "https://mirrors.aliyun.com/cygwin/",
    "https://cygwin.mirror.constant.com/",
    "https://www.cygwin.com/mirrors.html",
    "https://www.cygwin.com/mirrors.html#mirroradmin",
    "https://www.cygwin.com/mirrors.html#sitelist",
    "https://www.cygwin.com/mirrors-report.html",
    "https://polish-mirror.evolution-host.com/cygwin/",
    "https://cygwin.mirrors.hoobly.com/",
    "https://mirrors.huaweicloud.com/cygwin/",
    "https://mirrors.tencent.com/cygwin/",
    "https://mirrors.xmission.com/cygwin/",
    "https://mirror.checkdomain.de/cygwin/",
    "https://mirror.dogado.de/cygwin/",
    "https://www.gutscheinrausch.de/mirror/cygwin/",
    "https://mirror.clarkson.edu/cygwin/",
    "https://mirrors.rit.edu/cygwin/",
    "https://ftp.funet.fi/pub/mirrors/sourceware.org/pub/cygwin/",
    "https://mirrors.filigrane-technologie.fr/cygwin/",
    "https://mirror.isoc.org.il/pub/cygwin/",
    "https://sourceware.mirror.garr.it/cygwin/",
    "https://mirror.lagoon.nc/cygwin/",
    "https://mirror.koddos.net/cygwin/",
    "https://mirror-hk.koddos.net/cygwin/",
    "https://mirror.mangohost.net/cygwin/",
    "https://mirrors.netix.net/cygwin/",
    "https://cygwin.mirror.uk.sargasso.net/",
    "https://mirrors.sonic.net/cygwin/",
    "https://mirror.steadfast.net/cygwin/",
    "https://mirror.terrahost.no/cygwin/",
    "https://mirrors.dotsrc.org/cygwin/",
    "https://mirrors.kernel.org/sourceware/cygwin/",
    "https://www.mirrorservice.org/sites/sourceware.org/pub/cygwin/",
    "https://ftp.acc.umu.se/mirror/cygwin/",
    "https://download.nus.edu.sg/mirror/cygwin/",
    "https://cygwin.mirror.globo.tech/",
]


def escape_windows_path(filepath):
    return os.path.normpath(
        r"\\".join(
            [
                f'"{x}"' if i != 0 else x
                for i, x in enumerate(
                    pathlib.Path(os.path.normpath(os.path.abspath(filepath))).parts
                )
            ]
        )
    )


def list_files_from_folder(cygbinfolder, foldertoscan, withstat=True):
    def escape_spaces_cyg(text):
        if isinstance(text, bytes):
            return text.replace(b" ", b"\\ ")
        return text.replace(" ", "\\ ")

    cygbinfoldertmp = os.path.normpath(cygbinfolder.strip().strip(os.sep))
    findexe = os.path.normpath(rf"{cygbinfoldertmp}\find.exe")
    xargsexe = os.path.normpath(rf"{cygbinfoldertmp}\xargs.exe")
    statexe = os.path.normpath(rf"{cygbinfoldertmp}\stat.exe")

    ba = Bashsubprocess(
        os.sep.join(cygbinfolder.split(os.sep)[:-1]),
    )
    findpath = escape_spaces_cyg(ba.convert_path_win2cyg(os.path.normpath(findexe)))
    foldertoscan = escape_spaces_cyg(ba.convert_path_win2cyg(foldertoscan))
    xargspath = escape_spaces_cyg(ba.convert_path_win2cyg(os.path.normpath(xargsexe)))
    statpath = escape_spaces_cyg(ba.convert_path_win2cyg(os.path.normpath(statexe)))

    if withstat:
        cmd1 = ba.execute_capture(
            rf'''"{findpath}" "{foldertoscan}" -type f -print0 | "{xargspath}" -0 "{statpath}" --printf="\t%s\t%y\t%n\n"'''
        )
    else:
        cmd1 = ba.execute_capture(rf"""{findpath} {foldertoscan} -type f -print0""")

    stdo = cmd1.stdout_lines
    statsize, statdate = [], []
    if withstat:
        temp = [g.split(b"\t") for q in cmd1.stdout_lines if (g := q.strip())]
        statsinfo = [x[:2] for x in temp]
        stdo = [x[-1] for x in temp]
        asbin = stdo
        asutf8 = [x.decode("utf-8") for x in stdo]
        statsinfo = [
            [
                statsize.append(int(y.decode("utf-8")))
                if ini == 0
                else statdate.append(y.decode("utf-8"))
                for ini, y in enumerate(x)
            ]
            for x in statsinfo
        ]
    else:
        asbin = stdo[0]
        asutf8 = stdo[0].decode("utf-8")
        asbin = [g for x in asbin.split(b"\x00") if (g := x.strip())]
        asutf8 = [g for x in asutf8.split("\x00") if (g := x.strip())]
    asbinescaped = [x.replace(b" ", b"\\ ") for x in asbin]
    bytedata = b"\n".join(asbinescaped)
    cmd = (ba.cgypath_exe + " -w -o -f -").split()
    proc = subprocess.run(
        cmd, input=bytedata, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
    )
    outbin = proc.stdout
    outbinsplit = [g for x in outbin.splitlines() if (g := x.strip())]
    out = outbin.decode("utf-8", "ignore").splitlines()
    winescaped = [escape_windows_path(g) for x in out if (g := x.strip())]

    if withstat:
        PInfo = namedtuple(
            "PInfo",
            "p_cgy_bin p_cgy_bin_esc p_cyg_utf8 p_win_bin p_win_utf8 p_win_utf8_esc p_size p_date",
        )
        allto = [
            PInfo(*x)
            for x in zip(
                asbin,
                asbinescaped,
                asutf8,
                outbinsplit,
                out,
                winescaped,
                statsize,
                statdate,
            )
        ]
    else:
        PInfo = namedtuple(
            "PInfo",
            "p_cgy_bin p_cgy_bin_esc p_cyg_utf8 p_win_bin p_win_utf8 p_win_utf8_esc",
        )
        allto = [
            PInfo(*x)
            for x in zip(asbin, asbinescaped, asutf8, outbinsplit, out, winescaped)
        ]

    return allto


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
    Popen(f"taskkill /F /PID {pid} /T", shell=False)


def timer_thread(timer, pid):
    timer.start()
    timer.join()
    callback_func(pid)


def cyg2winpath(cyg_path, path):
    return (
        subprocess.run(f"{cyg_path} -w {path}", capture_output=True, shell=True)
        .stdout.strip(b"\n")
        .decode()
    )


def win2cgypath(cyg_path, path):
    return (
        subprocess.run(f"{cyg_path} -p {path}", capture_output=True, shell=True)
        .stdout.strip(b"\n")
        .decode()
    )


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
        shell=True,
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


def install_cygwin(cygfolder, mirrorsite="https://linorg.usp.br/cygwin/"):
    if not os.path.exists(cygfolder):
        os.makedirs(cygfolder)
    cygfolder = os.path.normpath(cygfolder).replace("/", "\\")
    battmp = get_tmpfile(".bat")
    bax = requests.get("https://cygwin.com/setup-x86_64.exe")
    with open(
        os.path.normpath(os.path.join(os.path.dirname(battmp), "cygwin-setup.exe")),
        mode="wb",
    ) as f:
        f.write(bax.content)
    bfile = rf"""
@ECHO OFF
REM -- Automates cygwin installation
REM -- Source: https://github.com/rtwolf/cygwin-auto-install
REM -- Based on: https://gist.github.com/wjrogers/1016065
 
SETLOCAL
 
REM -- Change to the directory of the executing batch file
CD %~dp0

REM -- Download the Cygwin installer
IF NOT EXIST cygwin-setup.exe (
    ECHO cygwin-setup.exe NOT found! Downloading installer...
    bitsadmin /transfer cygwinDownloadJob /download /priority normal https://cygwin.com/setup-x86_64.exe %CD%\\cygwin-setup.exe
) ELSE (
    ECHO cygwin-setup.exe found! Skipping installer download...
)
 
REM -- Configure our paths
SET SITE={mirrorsite}
SET LOCALDIR=%CD%
SET ROOTDIR={cygfolder}
 
REM -- These are the packages we will install (in addition to the default packages)
SET PACKAGES=mintty,wget,ctags,diffutils,git,git-completion,git-svn,stgit,mercurial
REM -- These are necessary for apt-cyg install, do not change. Any duplicates will be ignored.
SET PACKAGES=%PACKAGES%,wget,tar,gawk,bzip2,subversion
 
REM -- More info on command line options at: https://cygwin.com/faq/faq.html#faq.setup.cli
REM -- Do it!
ECHO *** INSTALLING DEFAULT PACKAGES
cygwin-setup --quiet-mode --no-desktop --download --local-install --no-verify -s %SITE% -l "%LOCALDIR%" -R "%ROOTDIR%"
ECHO.
ECHO.
ECHO *** INSTALLING CUSTOM PACKAGES
cygwin-setup -q -d -D -L -X -s %SITE% -l "%LOCALDIR%" -R "%ROOTDIR%" -P %PACKAGES%
 
REM -- Show what we did
ECHO.
ECHO.
ECHO cygwin installation updated
ECHO  - %PACKAGES%
ECHO.

ENDLOCAL
 

"""

    with open(battmp, mode="w", encoding="utf-8") as f:
        f.write(bfile)
    subprocess.run(battmp, shell=True)


class Bashsubprocess:
    def __init__(self, cygfolder, mirrorsite=None, addtopath=True):
        cgybinfolder = os.path.normpath(os.path.join(cygfolder, "bin"))
        rootfolder = os.path.normpath(cygfolder)
        self.folder = cgybinfolder
        installapt = False
        self.bash_exe = os.path.normpath(os.path.join(cgybinfolder, "bash.exe"))
        if not os.path.exists(cgybinfolder):
            ins = input("Cygwin not found. Do you want to install it? [Y/n]")
            if str(ins).strip().lower() in ["", "y"]:
                mirrorsiteuse = ""
                alreadyused = [""]

                while not os.path.exists(self.bash_exe):
                    if not mirrorsite:
                        while mirrorsiteuse in alreadyused:
                            mirrorsiteuse = random.choice(mirrorpages)
                            if mirrorsiteuse not in alreadyused:
                                alreadyused.append(mirrorsiteuse)
                                break
                    else:
                        mirrorsiteuse = mirrorsite
                    install_cygwin(rootfolder, mirrorsite=mirrorsiteuse)
                installapt = True
                if addtopath:
                    cva0 = add_to_path_current_user(
                        folders=[cgybinfolder],
                        remove_from_path=[],
                        beginning=True,
                    )
                    cva1 = add_to_path_all_users(
                        folders=[cgybinfolder],
                        remove_from_path=[],
                        beginning=True,
                    )

            else:
                try:
                    sys.exit(1)
                finally:
                    os._exit(1)

        if sys.path[0] != self.folder:
            sys.path.insert(0, self.folder)
        self._cmdadd = [self.bash_exe, "-c"]
        self.cgypath_exe = os.path.normpath(os.path.join(self.folder, "cygpath.exe"))
        if installapt:
            self.installapt()
        self.aptpath = os.path.normpath(os.path.join(self.folder, "apt"))
        self.aptpathcyg = self.convert_path_win2cyg(self.aptpath)# + ".sh"

    def apt_install(self, package):
        if not os.path.exists(self.aptpath):
           self.installapt()
        co = f"chmod +x {self.aptpathcyg}"
        cmd3 = self.execute_print_capture(co)
        workdir = os.getcwd()
        os.chdir(self.folder)
        os.system(rf'start "" "{self.bash_exe}" -c "apt install {package}"')
        sleep(1)
        os.chdir(workdir)

    def apt_remove(self, package):
        co = f"chmod +x {self.aptpathcyg}"
        cmd3 = self.execute_print_capture(co)
        workdir = os.getcwd()
        os.chdir(self.folder)
        os.system(rf'start "" "{self.bash_exe}" -c "apt remove {package}"')
        sleep(1)
        os.chdir(workdir)


    def installapt(self):
        installapt = r"""#!/bin/bash
# apt-cyg: install tool for Cygwin similar to debian apt-get
#
# The MIT License (MIT)
#
# Copyright (c) 2013 Trans-code Design
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

if [ ${BASH_VERSINFO}${BASH_VERSINFO[1]} -lt 42 ]
then
  echo 'Bash version 4.2+ required'
  exit
fi

usage="\
NAME
  apt-cyg - package manager utility

SYNOPSIS
  apt-cyg [operation] [options] [targets]

DESCRIPTION
  apt-cyg is a package management utility that tracks installed packages on a
  Cygwin system. Invoking apt-cyg involves specifying an operation with any
  potential options and targets to operate on. A target is usually a package
  name, file name, URL, or a search string. Targets can be provided as command
  line arguments.

OPERATIONS
  install
    Install package(s).

  remove
    Remove package(s) from the system.

  update
    Download a fresh copy of the master package list (setup.ini) from the
    server defined in setup.rc.

  download
    Retrieve package(s) from the server, but do not install/upgrade anything.

  show
    Display information on given package(s).

  depends
    Produce a dependency tree for a package.

  rdepends
    Produce a tree of packages that depend on the named package.

  list
    Search each locally-installed package for names that match regexp. If no
    package names are provided in the command line, all installed packages will
    be queried.

  listall
    This will search each package in the master package list (setup.ini) for
    names that match regexp.

  category
    Display all packages that are members of a named category.

  listfiles
    List all files owned by a given package. Multiple packages can be specified
    on the command line.

  search
    Search for downloaded packages that own the specified file(s). The path can
    be relative or absolute, and one or more files can be specified.

  searchall
    Search cygwin.com to retrieve file information about packages. The provided
    target is considered to be a filename and searchall will return the
    package(s) which contain this file.

  mirror
    Set the mirror; a full URL to a location where the database, packages, and
    signatures for this repository can be found. If no URL is provided, display
    current mirror.

  cache
    Set the package cache directory. If a file is not found in cache directory,
    it will be downloaded. Unix and Windows forms are accepted, as well as
    absolute or regular paths. If no directory is provided, display current
    cache.

OPTIONS
  --nodeps
    Specify this option to skip all dependency checks.

  --version
    Display version and exit.
"

version="\
apt-cyg version 1

The MIT License (MIT)

Copyright (c) 2005-9 Stephen Jungels
"

function wget {
  if command wget -h &>/dev/null
  then
    command wget "$@"
  else
    warn wget is not installed, using lynx as fallback
    set "${*: -1}"
    lynx -source "$1" > "${1##*/}"
  fi
}

function find-workspace {
  # default working directory and mirror

  # work wherever setup worked last, if possible
  cache=$(awk '
  BEGIN {
    RS = "\n\\<"
    FS = "\n\t"
  }
  $1 == "last-cache" {
    print $2
  }
  ' /etc/setup/setup.rc)

  mirror=$(awk '
  /last-mirror/ {
    getline
    print $1
  }
  ' /etc/setup/setup.rc)
  mirrordir=$(sed '
  s / %2f g
  s : %3a g
  ' <<< "$mirror")

  mkdir -p "$cache/$mirrordir/$arch"
  cd "$cache/$mirrordir/$arch"
  if [ -e setup.ini ]
  then
    return 0
  else
    get-setup
    return 1
  fi
}

function get-setup {
  touch setup.ini
  mv setup.ini setup.ini-save
  wget -N $mirror/$arch/setup.bz2
  if [ -e setup.bz2 ]
  then
    bunzip2 setup.bz2
    mv setup setup.ini
    echo Updated setup.ini
  else
    echo Error updating setup.ini, reverting
    mv setup.ini-save setup.ini
  fi
}

function check-packages {
  if [[ $pks ]]
  then
    return 0
  else
    echo No packages found.
    return 1
  fi
}

function warn {
  printf '\e[1;31m%s\e[m\n' "$*" >&2
}

function apt-update {
  if find-workspace
  then
    get-setup
  fi
}

function apt-category {
  check-packages
  find-workspace
  for pkg in "${pks[@]}"
  do
    awk '
    $1 == "@" {
      pck = $2
    }
    $1 == "category:" && $0 ~ query {
      print pck
    }
    ' query="$pks" setup.ini
  done
}

function apt-list {
  local sbq
  for pkg in "${pks[@]}"
  do
    let sbq++ && echo
    awk 'NR>1 && $1~pkg && $0=$1' pkg="$pkg" /etc/setup/installed.db
  done
  let sbq && return
  awk 'NR>1 && $0=$1' /etc/setup/installed.db
}

function apt-listall {
  check-packages
  find-workspace
  local sbq
  for pkg in "${pks[@]}"
  do
    let sbq++ && echo
    awk '$1~pkg && $0=$1' RS='\n\n@ ' FS='\n' pkg="$pkg" setup.ini
  done
}

function apt-listfiles {
  check-packages
  find-workspace
  local pkg sbq
  for pkg in "${pks[@]}"
  do
    (( sbq++ )) && echo
    if [ ! -e /etc/setup/"$pkg".lst.gz ]
    then
      download "$pkg"
    fi
    gzip -cd /etc/setup/"$pkg".lst.gz
  done
}

function apt-show {
  find-workspace
  check-packages
  for pkg in "${pks[@]}"
  do
    (( notfirst++ )) && echo
    awk '
    $1 == query {
      print
      fd++
    }
    END {
      if (! fd)
        print "Unable to locate package " query
    }
    ' RS='\n\n@ ' FS='\n' query="$pkg" setup.ini
  done
}

function apt-depends {
  find-workspace
  check-packages
  for pkg in "${pks[@]}"
  do
    awk '
    @include "join"
    $1 == "@" {
      apg = $2
    }
    $1 == "requires:" {
      for (z=2; z<=NF; z++)
        reqs[apg][z-1] = $z
    }
    END {
      prpg(ENVIRON["pkg"])
    }
    function smartmatch(small, large,    values) {
      for (each in large)
        values[large[each]]
      return small in values
    }
    function prpg(fpg) {
      if (smartmatch(fpg, spath)) return
      spath[length(spath)+1] = fpg
      print join(spath, 1, length(spath), " > ")
      if (isarray(reqs[fpg]))
        for (each in reqs[fpg])
          prpg(reqs[fpg][each])
      delete spath[length(spath)]
    }
    ' setup.ini
  done
}

function apt-rdepends {
  find-workspace
  for pkg in "${pks[@]}"
  do
    awk '
    @include "join"
    $1 == "@" {
      apg = $2
    }
    $1 == "requires:" {
      for (z=2; z<=NF; z++)
        reqs[$z][length(reqs[$z])+1] = apg
    }
    END {
      prpg(ENVIRON["pkg"])
    }
    function smartmatch(small, large,    values) {
      for (each in large)
        values[large[each]]
      return small in values
    }
    function prpg(fpg) {
      if (smartmatch(fpg, spath)) return
      spath[length(spath)+1] = fpg
      print join(spath, 1, length(spath), " < ")
      if (isarray(reqs[fpg]))
        for (each in reqs[fpg])
          prpg(reqs[fpg][each])
      delete spath[length(spath)]
    }
    ' setup.ini
  done
}

function apt-download {
  check-packages
  find-workspace
  local pkg sbq
  for pkg in "${pks[@]}"
  do
    (( sbq++ )) && echo
    download "$pkg"
  done
}

function download {
  local pkg digest digactual
  pkg=$1
  # look for package and save desc file

  awk '$1 == pc' RS='\n\n@ ' FS='\n' pc=$pkg setup.ini > desc
  if [ ! -s desc ]
  then
    echo Unable to locate package $pkg
    exit 1
  fi

  # download and unpack the bz2 or xz file

  # pick the latest version, which comes first
  set -- $(awk '$1 == "install:"' desc)
  if (( ! $# ))
  then
    echo 'Could not find "install" in package description: obsolete package?'
    exit 1
  fi

  dn=$(dirname $2)
  bn=$(basename $2)

  # check the md5
  digest=$4
  case ${#digest} in
   32) hash=md5sum    ;;
  128) hash=sha512sum ;;
  esac
  mkdir -p "$cache/$mirrordir/$dn"
  cd "$cache/$mirrordir/$dn"
  if ! test -e $bn || ! $hash -c <<< "$digest $bn"
  then
    wget -O $bn $mirror/$dn/$bn
    $hash -c <<< "$digest $bn" || exit
  fi

  tar tf $bn | gzip > /etc/setup/"$pkg".lst.gz
  cd ~-
  mv desc "$cache/$mirrordir/$dn"
  echo $dn $bn > /tmp/dwn
}

function apt-search {
  check-packages
  echo Searching downloaded packages...
  for pkg in "${pks[@]}"
  do
    key=$(type -P "$pkg" | sed s./..)
    [[ $key ]] || key=$pkg
    for manifest in /etc/setup/*.lst.gz
    do
      if gzip -cd $manifest | grep -q "$key"
      then
        package=$(sed '
        s,/etc/setup/,,
        s,.lst.gz,,
        ' <<< $manifest)
        echo $package
      fi
    done
  done
}

function apt-searchall {
  cd /tmp
  for pkg in "${pks[@]}"
  do
    printf -v qs 'text=1&arch=%s&grep=%s' $arch "$pkg"
    wget -O matches cygwin.com/cgi-bin2/package-grep.cgi?"$qs"
    awk '
    NR == 1 {next}
    mc[$1]++ {next}
    /-debuginfo-/ {next}
    /^cygwin32-/ {next}
    {print $1}
    ' FS=-[[:digit:]] matches
  done
}

function apt-install {
  check-packages
  find-workspace
  local pkg dn bn requires wr package sbq script
  for pkg in "${pks[@]}"
  do

  if grep -q "^$pkg " /etc/setup/installed.db
  then
    echo Package $pkg is already installed, skipping
    continue
  fi
  (( sbq++ )) && echo
  echo Installing $pkg

  download $pkg
  read dn bn </tmp/dwn
  echo Unpacking...

  cd "$cache/$mirrordir/$dn"
  tar -x -C / -f $bn
  # update the package database

  awk '
  ins != 1 && pkg < $1 {
    print pkg, bz, 0
    ins = 1
  }
  1
  END {
    if (ins != 1) print pkg, bz, 0
  }
  ' pkg="$pkg" bz=$bn /etc/setup/installed.db > /tmp/awk.$$
  mv /etc/setup/installed.db /etc/setup/installed.db-save
  mv /tmp/awk.$$ /etc/setup/installed.db

  [ -v nodeps ] && continue
  # recursively install required packages

  requires=$(awk '$1=="requires", $0=$2' FS=': ' desc)
  cd ~-
  wr=0
  if [[ $requires ]]
  then
    echo Package $pkg requires the following packages, installing:
    echo $requires
    for package in $requires
    do
      if grep -q "^$package " /etc/setup/installed.db
      then
        echo Package $package is already installed, skipping
        continue
      fi
      apt-cyg install --noscripts $package || (( wr++ ))
    done
  fi
  if (( wr ))
  then
    echo some required packages did not install, continuing
  fi

  # run all postinstall scripts

  [ -v noscripts ] && continue
  find /etc/postinstall -name '*.sh' | while read script
  do
    echo Running $script
    $script
    mv $script $script.done
  done
  echo Package $pkg installed

  done
}

function apt-remove {
  check-packages
  cd /etc
  cygcheck awk bash bunzip2 grep gzip mv sed tar xz > setup/essential.lst
  for pkg in "${pks[@]}"
  do

  if ! grep -q "^$pkg " setup/installed.db
  then
    echo Package $pkg is not installed, skipping
    continue
  fi

  if [ ! -e setup/"$pkg".lst.gz ]
  then
    warn Package manifest missing, cannot remove $pkg. Exiting
    exit 1
  fi
  gzip -dk setup/"$pkg".lst.gz
  awk '
  NR == FNR {
    if ($NF) ess[$NF]
    next
  }
  $NF in ess {
    exit 1
  }
  ' FS='[/\\\\]' setup/{essential,$pkg}.lst
  esn=$?
  if [ $esn = 0 ]
  then
    echo Removing $pkg
    if [ -e preremove/"$pkg".sh ]
    then
      preremove/"$pkg".sh
      rm preremove/"$pkg".sh
    fi
    mapfile dt < setup/"$pkg".lst
    for each in ${dt[*]}
    do
      [ -f /$each ] && rm /$each
    done
    for each in ${dt[*]}
    do
      [ -d /$each ] && rmdir --i /$each
    done
    rm -f setup/"$pkg".lst.gz postinstall/"$pkg".sh.done
    awk -i inplace '$1 != ENVIRON["pkg"]' setup/installed.db
    echo Package $pkg removed
  fi
  rm setup/"$pkg".lst
  if [ $esn = 1 ]
  then
    warn apt-cyg cannot remove package $pkg, exiting
    exit 1
  fi

  done
}

function apt-mirror {
  if [ "$pks" ]
  then
    awk -i inplace '
    1
    /last-mirror/ {
      getline
      print "\t" pks
    }
    ' pks="$pks" /etc/setup/setup.rc
    echo Mirror set to "$pks".
  else
    awk '
    /last-mirror/ {
      getline
      print $1
    }
    ' /etc/setup/setup.rc
  fi
}

function apt-cache {
  if [ "$pks" ]
  then
    vas=$(cygpath -aw "$pks")
    awk -i inplace '
    1
    /last-cache/ {
      getline
      print "\t" vas
    }
    ' vas="${vas//\\/\\\\}" /etc/setup/setup.rc
    echo Cache set to "$vas".
  else
    awk '
    /last-cache/ {
      getline
      print $1
    }
    ' /etc/setup/setup.rc
  fi
}

if [ -p /dev/stdin ]
then
  mapfile -t pks
fi

# process options
until [ $# = 0 ]
do
  case "$1" in

    --nodeps)
      nodeps=1
      shift
    ;;

    --noscripts)
      noscripts=1
      shift
    ;;

    --version)
      printf "$version"
      exit
    ;;

    update)
      command=$1
      shift
    ;;

    list | cache  | remove | depends | listall  | download | listfiles |\
    show | mirror | search | install | category | rdepends | searchall )
      if [[ $command ]]
      then
        pks+=("$1")
      else
        command=$1
      fi
      shift
    ;;

    *)
      pks+=("$1")
      shift
    ;;

  esac
done

set -a

if type -t apt-$command | grep -q function
then
  readonly arch=${HOSTTYPE/i6/x}
  apt-$command
else
  printf "$usage"
fi
"""
        oldwd = os.getcwd()
        cygfolderbin = self.folder
        os.chdir(cygfolderbin)

        aptinstallfile = os.path.normpath(os.path.join(cygfolderbin, "apt"))

        with open(aptinstallfile, mode="w", encoding="utf-8", newline="\n") as f:
            f.write(installapt)
        self.exec_sh_file(aptinstallfile)
        os.chdir(oldwd)

    def execute_print_capture(self, cmd):
        if not isinstance(cmd, list):
            cmd = [cmd]
        wholcmd = self._cmdadd + cmd

        p = Popen(wholcmd, shell=True, print_output=True)
        return p

    def execute_capture(self, cmd):
        if not isinstance(cmd, list):
            cmd = [cmd]
        wholcmd = self._cmdadd + cmd
        p = Popen(wholcmd, print_output=False, shell=True)
        return p

    def convert_path_cyg2win(self, path):
        return cyg2winpath(self.cgypath_exe, escape_windows_path(path))

    def convert_path_win2cyg(self, path):
        escpath = escape_windows_path(path)
        return win2cgypath(self.cgypath_exe, escpath)

    def exec_sh_url(self, bashscr, printoutput=True):
        tmpbash = get_tmpfile('.sh')
        res=requests.get(bashscr)
        with open(tmpbash, mode='wb') as f:
            f.write(res.content)
        bashscr = tmpbash
        cpa = self.convert_path_win2cyg(bashscr)
        co = [f"chmod +x {cpa}", cpa]
        if printoutput:
            cmd3 = self.execute_print_capture(co[0])
            cmd3 = self.execute_print_capture(co[1])
        else:
            cmd3 = self.execute_capture(co[0])
            cmd3 = self.execute_capture(co[1])
        return cmd3

    def exec_sh_file(self, bashscr, printoutput=True):
        cpa = self.convert_path_win2cyg(bashscr)
        co = [f"chmod +x {cpa}", cpa]
        if printoutput:
            cmd3 = self.execute_print_capture(co[0])
            cmd3 = self.execute_print_capture(co[1])
        else:
            cmd3 = self.execute_capture(co[0])
            cmd3 = self.execute_capture(co[1])
        return cmd3

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

    def get_list_of_files_no_stat(self, folder):
        return list_files_from_folder(
            foldertoscan=folder, withstat=False, cygbinfolder=self.folder
        )

    def get_list_of_files_with_stat(self, folder):
        return list_files_from_folder(
            foldertoscan=folder, withstat=True, cygbinfolder=self.folder
        )
