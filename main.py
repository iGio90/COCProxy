import frida
import os
import sys


def parse_message(message, data):
    print(message)


def run_cmd(cmd):
    os.system(cmd)


package_name = "com.supercell.clashofclans"

# start frida server
run_cmd("adb shell su -c setenforce 0")
run_cmd("adb shell su -c killall -9 frida")
run_cmd("adb shell su -c frida &")

print("[*] Killing " + package_name)
run_cmd("adb shell am force-stop " + package_name)
print("[*] Starting " + package_name)
run_cmd("adb shell monkey -p " + package_name + " -c android.intent.category.LAUNCHER 1")

process = frida.get_usb_device().attach(package_name)
print("Frida attached.")
script = process.create_script(open("inject.js", "r").read())
print("Dumper loaded.")
script.on('message', parse_message)
print("parse_message registered within script object.")
script.load()
sys.stdin.read()
