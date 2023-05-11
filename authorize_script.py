import os
import json
import subprocess
import platform
import sys
#  > login-code.txt 2>&1
print('az login --use-device-code > ' + sys.argv[1] + ' 2>&1')
logged_in_account = json.loads(subprocess.check_output('az login --use-device-code > ' + sys.argv[1] + ' 2>&1', shell=True).decode('utf-8'))

print(f"logged_in_account = {logged_in_account[0]['user']['name']}")
print(f"subscription_id = {logged_in_account[0]['id']}" )
