import os, subprocess, pickle, yaml, hashlib, requests

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
api_key = "sk_live_0123456789abcdefghij"
DEBUG = True


def run(cmd):
    os.system("ls " + cmd)                          # command injection
    subprocess.call("echo " + cmd, shell=True)      # shell=True


def lookup(db, name):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # SQL injection
    return cur.fetchall()


def load(data):
    return pickle.loads(data)                       # insecure deserialization


def conf(s):
    return yaml.load(s)                             # yaml.load without SafeLoader


def hashpw(p):
    return hashlib.md5(p.encode()).hexdigest()      # weak hash for a password


def fetch(u):
    return requests.get(u, verify=False)            # TLS verification disabled


def ev(x):
    return eval(x)                                  # eval on dynamic input
