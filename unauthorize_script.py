import sys
import json
import subprocess

if __name__ == '__main__':
    LOGGED_IN_USER = sys.argv[1]
    subprocess.check_output(f'az logout --username {LOGGED_IN_USER}', shell=True).decode('utf-8')