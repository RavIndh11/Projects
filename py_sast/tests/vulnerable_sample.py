import hashlib
import subprocess

def do_eval(user_input):
    # SAST-001
    return eval(user_input)

def do_exec(user_input):
    # SAST-001
    exec(user_input)

def hash_password(password):
    # SAST-002
    m = hashlib.md5()
    m.update(password.encode())

    # SAST-002
    s = hashlib.sha1()
    s.update(password.encode())
    return m.hexdigest()

def run_command(cmd):
    # SAST-003
    subprocess.call(cmd, shell=True)

    # SAST-003
    subprocess.Popen(cmd, shell=True)

    # SAST-003
    subprocess.run(cmd, shell=True)

def safe_command(cmd):
    # This should not be flagged
    subprocess.call(cmd)
