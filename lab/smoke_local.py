#!/usr/bin/env python3
"""mTLS smoke test: three OS processes, loopback IPs, no shared IPC (default: toy).
Run after compiling pqpep-lab; requires Python 3, sh and openssl. It does not
benchmark paper parameters or replace the three-container Docker lab.
"""
import argparse
import os
import pathlib
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/pqpep-lab')
parser.add_argument('--profile', choices=['toy', 'paper'], default='toy')
args = parser.parse_args()
binary = str(pathlib.Path(args.binary).resolve())
root = pathlib.Path(tempfile.mkdtemp(prefix='pqpep-role-smoke-'))
processes, handles = [], []
success = False

def port(host):
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]

def ready(log, proc):
    for _ in range(480):
        if proc.poll() is not None:
            raise RuntimeError(f'service exited: {log.read_text(errors="replace")}')
        if '[READY]' in log.read_text(errors='replace'):
            return
        time.sleep(0.25)
    raise RuntimeError('service readiness timeout')

try:
    subprocess.run([binary, 'provision', str(root), args.profile], check=True)
    # Exercise upgrading existing material without regenerating any key.
    (root / 'b/lab-reference.bin').unlink()
    subprocess.run([binary, 'reference', str(root)], check=True)
    assert subprocess.run([binary, 'reference', str(root)], capture_output=True).returncode != 0
    subprocess.run(['sh', 'lab/make-certs.sh', str(root)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t_addr, b_addr = f'127.0.0.2:{port("127.0.0.2")}', f'127.0.0.3:{port("127.0.0.3")}'
    for role, folder, address in [('transcryptor', 'transcryptor', t_addr), ('recipient', 'b', b_addr)]:
        log = root / f'{role}.log'
        handle = log.open('w'); handles.append(handle)
        proc = subprocess.Popen([binary, role, str(root / folder), address], stdout=handle, stderr=handle)
        processes.append(proc); ready(log, proc)
    result = subprocess.run([binary, 'source', str(root / 'a'), t_addr, b_addr],
                            check=True, capture_output=True, text=True, timeout=1800)
    print(result.stdout)
    recipient_log = (root / 'recipient.log').read_text()
    assert '[B] Opened response:' in recipient_log
    assert '[PASS] PID equality: all 32 bytes' in recipient_log
    assert '[PASS] Attribute equality: ALL' in recipient_log
    assert 'B acknowledged EXACT PID and ALL attribute equality' in result.stdout
    # A valid encrypted request for a different ID must NOT get a success ACK.
    wrong_env = dict(os.environ, PQPEP_LAB_ID='deliberately-wrong-lab-identifier')
    negative = subprocess.run([binary, 'source', str(root / 'a'), t_addr, b_addr],
                              capture_output=True, text=True, timeout=1800, env=wrong_env)
    assert negative.returncode != 0, 'wrong PID unexpectedly accepted'
    assert 'acknowledged EXACT' not in negative.stdout
    assert 'PID equality FAILED' in (root / 'recipient.log').read_text()
    print('[PASS] Wrong identifier rejected at B: no verified acknowledgment returned.')
    # B is CA-authenticated but is not authorized to submit source requests.
    context = ssl.create_default_context(cafile=str(root / 'b/ca.pem'))
    context.load_cert_chain(str(root / 'b/cert.pem'), str(root / 'b/key.pem'))
    host, number = t_addr.rsplit(':', 1)
    rejected = False
    try:
        with socket.create_connection((host, int(number)), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname='transcryptor') as tls:
                tls.sendall(struct.pack('>Q', 1) + b'x')
                rejected = tls.recv(8) == b''
    except (ssl.SSLError, ConnectionError):
        rejected = True
    assert rejected, 'recipient certificate unexpectedly accepted as source'
    print('[PASS] A/T/B ran in distinct processes and exchanged actual ciphertexts over mTLS.')
    print('[PASS] CA-signed recipient certificate rejected at the source-only transcryptor endpoint.')
    print((root / 'recipient.log').read_text())
    success = True
finally:
    for process in processes:
        process.terminate()
    for process in processes:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
    for handle in handles:
        handle.close()
    if success:
        shutil.rmtree(root)
    else:
        print(f"Failure diagnostics and private test materials retained in: {root}")
