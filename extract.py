#!/usr/bin/python3

from re import search
from subprocess import run, Popen, check_output, PIPE, call, DEVNULL
from os import path, remove
from pathlib import Path
from argparse import ArgumentParser
from uuid import uuid4
from shutil import rmtree
from sys import exit

cert_folder = "certs_extracted"

parser = ArgumentParser(description='Extracts PKCS7 formatted certificates and outputs PEM certificates')
parser.add_argument('pkcs7',
                    help="PKCS7 input file to extract certificates from")
parser.add_argument('-d', '--dest',
                    metavar='destination',
                    nargs='?', 
                    default=cert_folder,
                    help=f'outputs to [destination] (defaults to {cert_folder})')
parser.add_argument('-s','--split',
                    action='store_true',
                    help='split the certificates into separate files')
parser.add_argument('-v','--verbose',
                    action='store_true',
                    help='verbose output')
parser.add_argument('--version', 
                    action='version', 
                    version="Certificate Extractor -- Version 0.2.0")
parser.add_argument('--acas',
                    action='store_true', 
                    help="install certificates to Tenable Security Center")
args = parser.parse_args()

openssl_pkcs7_command = ["openssl", "pkcs7", "-in", args.pkcs7]
openssl_x509_command = ["openssl", "x509", "-in"]

def clear_path():
    if path.exists(args.dest):
        rmtree(args.dest)

def make_path():
    clear_path()
    if path.exists(args.dest):
        if args.verbose:
            print(f'{args.dest} directory already exists.')
    else:
        if args.verbose:
            print(f"Creating {args.dest}...", end=" ")
        dir = Path(args.dest)
        dir.mkdir(parents=True, exist_ok=True)
        if args.verbose:
            print("created.")

def create_pem_file(is_pem: bool = False) -> str:
    pem_file = str(uuid4()) + ".pem"
    if is_pem:
        run(openssl_pkcs7_command + ["-print_certs", "-out", pem_file])
    else:
        run(openssl_pkcs7_command + ["-print_certs", "-inform", "DER", "-out", pem_file])
    return pem_file

def read_certs(pem_file: str) -> list:
    certs = []
    cert = ""
    start_line = False
    with open(pem_file, "r") as file:
        for line in file.readlines():
            if start_line:
                cert += line
            if line.startswith('-----BEGIN CERTIFICATE-----'):
                start_line = True
                cert += line
            if line.startswith('-----END CERTIFICATE-----'):
                start_line = False
                certs.append(cert)
                cert = ""
    return certs

def write_certs(certs: list) -> list:
    cert_files = []
    if args.split or args.acas:
        if args.verbose:
            print("Writing individual certificates to files...")

        for cert in certs:
            echo = Popen(["echo", cert], stdout=PIPE)
            output = check_output(["openssl", 
                                    "x509", 
                                    "-text",
                                    "-noout"], stdin=echo.stdout).decode('utf-8')
            ca_extraction = search("Subject:.*CN = (?P<ca>.*)", output)
            ca = ca_extraction.group(1)
            ca = ca.replace(" ", "_") + ".pem"
            
            if args.verbose:
                print(f"{args.dest}/{ca}")

            cert_file = path.join(args.dest, ca)
            cert_files.append(cert_file)
            with open(cert_file, "w") as file:
                file.write(cert)
    else:
        cert_file = path.join(args.dest, "certs.pem")
        for cert in certs:
            with open(cert_file, "a") as file:
                file.write(cert)
    return cert_files

def detect_pem() -> bool:
    if args.verbose:
        print(f"Determining format of {args.pkcs7}...", end=" ")

    if call(openssl_pkcs7_command, stderr=DEVNULL, stdout=DEVNULL) == 0:
        if args.verbose:
            print("PEM detected.")
        return True
    elif call(openssl_pkcs7_command + ["-inform", "DER"], stderr=DEVNULL, stdout=DEVNULL) == 0:
        if args.verbose:
            print("DER detected.")
        return False
    else:
        print(f"{args.pkcs7} isn't a DER or PEM formatted PKCS7")
        exit(1)

def install_acas(cert_files: list):
    if path.exists("/opt/sc/support/bin/php"):
        for cert in cert_files:
            run(["/opt/sc/support/bin/php", "/opt/sc/src/tools/installCA.php", cert])
    print('Security Center not found, or not installed in default location.')
    exit(1)

def restart_security_center():
    print('Succesfully installed certificates in Security Center')
    while True:
        result = input('Restart Security Center [yes/no]?')
        if result == 'yes':
            run(['systemctl', 'restart', 'SecurityCenter'])
            break
        if result == 'no':
            break

if __name__ == '__main__':
    make_path()
    is_pem = detect_pem()
    pem_file = create_pem_file(is_pem)
    certs = read_certs(pem_file)
    remove(pem_file)
    cert_files = write_certs(certs)
    print(f"Successfully extracted {len(certs)} certificates to {args.dest} in PEM format.")

    if args.acas:
        install_acas(cert_files)
        restart_security_center()
