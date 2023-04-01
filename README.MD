# Executes Cygwin bash scripts/commands in Python, captures and prints the output

## pip install cygsubprocess

### Tested against Windows 10 / Python 3.10 / Anaconda / cygcheck (cygwin) 3.4.6


```python

from cygsubprocess import Bashsubprocess
ba = Bashsubprocess(
    bash_exe=r"C:\tools\cygwin\bin\bash.exe",
    cgypath_exe=r"C:\tools\cygwin\bin\cygpath.exe",
)
ba.convert_path_cyg2win("/cygdrive/c/Users/hansc/Downloads/ClipAngel 2.09")
# r'C:\Users\hansc\Downloads\ClipAngel 2.09'

ba.convert_path_win2cyg(path=r"C:\Users\hansc\Downloads\ClipAngel 2.09")
#  '/cygdrive/c/Users/hansc/Downloads/ClipAngel 2.09'
cmd1 = ba.execute_capture("ls -la")
print(cmd1.stdout_lines[:5])

cmd2 = ba.execute_capture(["ls -la | grep 'py'"])
print(cmd2.stdout_lines[:5])


cmd1 = ba.execute_print_capture("ls -la")
print(cmd1.stdout_lines[:5])

cmd2 = ba.execute_print_capture(["ls -la | grep 'py'"])
print(cmd2.stdout_lines[:5])

# gist download
scriptexec = r"""
slugify(){ echo "$1" | iconv -t ascii//TRANSLIT | sed -r s/[^a-zA-Z0-9]+/-/g | sed -r s/^-+\|-+$//g | tr A-Z a-z; }
cnt=0; gh gist list --limit 3 | cut -f1,2 | tac | while read id name; do ((cnt++)); gh gist clone $id $cnt-`slugify "$name"`; done
"""
cmd4 = ba.execute_print_capture(scriptexec)
print(cmd4.stdout_lines)


bashscr = """
#!/bin/bash
# set the STRING variable
STRING="Hello World!"
# print the contents of the variable on screen
echo $STRING
"""
bashtofile = ba.exec_sh_to_file(bashscr, printoutput=False)
print(bashtofile.stdout_lines)

bashscr = r"""
#!/bin/bash
salary=1000
expenses=800
#Check if salary and expenses are equal
if [ $salary == $expenses ];
then
    echo "Salary and expenses are equal"
#Check if salary and expenses are not equal
elif [ $salary != $expenses ];
then
    echo "Salary and expenses are not equal"
fi
"""
bashtofile2 = ba.exec_sh_directly(bashscr, printoutput=True)
print(bashtofile2.stdout_lines)

....

# b'-rwxr-x---+ 1 Administrators hansc    25749 Mar 31 23:52 trayinfo.py.bak\n'
# b'-rwxr-x---+ 1 Administrators hansc      671 Apr  1 09:50 trayinfotest.py\n'
# b'-rwxr-x---+ 1 Administrators hansc    25878 Apr  1 09:34 traymenuxxxxxxxxxx.py\n'
# b'-rwxr-x---+ 1 Administrators hansc     4329 Apr  1 03:12 tw.py\n'
# b'-rwxr-x---+ 1 Administrators hansc     8095 Apr  1 08:48 win10ctypestoastxxxxxxxxxx.py\n'
# [b'drwxr-x---+ 1 hansc          hansc        0 Apr  1 13:01 1-pyde-py\n', b'drwxr-x---+ 1 hansc          hansc        0 Apr  1 13:14 1-stra-py\n', b'drwxr-x---+ 1 hansc          hansc        0 Apr  1 13:14 10-cygwinco-py\n', b'drwxr-x---+ 1 hansc          hansc        0 Apr  1 13:01 10-tracealllines-py\n', b'drwxr-x---+ 1 hansc          hansc        0 Apr  1 13:01 2-stra-py\n']
# b"Cloning into '1-tracealllines-py'...\n"
# b"Cloning into '2-cygwinco-py'...\n"
# b"Cloning into '3-cygwinco-py'...\n"
# []
# [b'Hello World!\n']
# b'Salary and expenses are not equal\n'
# [b'Salary and expenses are not equal\n']
....
```
