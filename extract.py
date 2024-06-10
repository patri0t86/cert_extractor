#!/usr/bin/python3

from re import search
from subprocess import run, Popen, check_output, PIPE, call, DEVNULL
from os import path, remove
from pathlib import Path
from argparse import ArgumentParser
from uuid import uuid4
from shutil import rmtree, copy2
from sys import exit

cert_folder = "certs_extracted"

parser = ArgumentParser(description="""
                        Extracts PKCS7 formatted certificates and outputs PEM certificates.
                        Requires OpenSSL package installed via package manager.
                        Certificates can be automatically installed to the OS certificate store (Red Hat distros) or Tenable Security Center.""")
parser.add_argument('pkcs7',
                    help="PKCS7 input file to extract certificates from")
parser.add_argument('--acas',
                    action='store_true', 
                    help="install certificates to Tenable Security Center (recommend as tns user)")
parser.add_argument('--os',
                    action='store_true', 
                    help="install certificates to OS certificate trust store (requires root)")
parser.add_argument('-d',
                    metavar='<dest>',
                    default=cert_folder,
                    help=f'outputs to [destination] (defaults to {cert_folder})')
parser.add_argument('-s',
                    action='store_true',
                    help='split the certificates into separate files')
parser.add_argument('-v',
                    action='store_true',
                    help='verbose output')
parser.add_argument('--version',
                    action='version', 
                    version="Certificate Extractor -- Version 0.3.0")
args = parser.parse_args()

openssl_pkcs7_command = ["openssl", "pkcs7", "-in", args.pkcs7]
openssl_x509_command = ["openssl", "x509", "-in"]

def clear_path():
    if path.exists(args.d):
        rmtree(args.d)

def make_path():
    clear_path()
    if path.exists(args.d):
        if args.v:
            print(f'{args.d} directory already exists.')
    else:
        if args.v:
            print(f"Creating {args.d}...", end=" ")
        dir = Path(args.d)
        dir.mkdir(parents=True, exist_ok=True)
        if args.v:
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
    if args.s or args.acas:
        if args.v:
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
            
            if args.v:
                print(f"{args.d}/{ca}")

            cert_file = path.join(args.d, ca)
            cert_files.append(cert_file)
            with open(cert_file, "w") as file:
                file.write(cert)
    else:
        cert_file = path.join(args.d, "certs.pem")
        for cert in certs:
            with open(cert_file, "a") as file:
                file.write(cert)
        cert_files.append(cert_file)
    print(f"Successfully extracted {len(certs)} certificates to {args.d} in PEM format.")
    return cert_files

def detect_pem() -> bool:
    if args.v:
        print(f"Determining format of {args.pkcs7}...", end=" ")

    if call(openssl_pkcs7_command, stderr=DEVNULL, stdout=DEVNULL) == 0:
        if args.v:
            print("PEM detected.")
        return True
    elif call(openssl_pkcs7_command + ["-inform", "DER"], stderr=DEVNULL, stdout=DEVNULL) == 0:
        if args.v:
            print("DER detected.")
        return False
    else:
        print(f"{args.pkcs7} isn't a DER or PEM formatted PKCS7")
        exit(1)

def install_certs_acas(cert_files: list):
    try:
        for cert in cert_files:
            run(["/opt/sc/support/bin/php", "/opt/sc/src/tools/installCA.php", cert])
        print('Succesfully installed certificates in Security Center. Don\'t forget to restart Security Center.')
    except PermissionError:
        print("You don't have permission to install certificates to Security Center.")
    except FileNotFoundError:
        print('Security Center not found, or not installed in default location.') 

def install_certs_os(cert_files: list):
    os_cert_path = "/etc/pki/ca-trust/source/anchors"
    try:
        for cert in cert_files:
            copy2(cert, os_cert_path)
        run(["update-ca-trust"])
    except FileNotFoundError:
        with open('/etc/os-release', 'r') as release:
            data = release.read()
            name = search("^PRETTY_NAME=\"(?P<distro>.*)\"", data)
            print(f"This operating system does not appear to be a Red Hat family distro, got {name.group(1)}.")
    except PermissionError:
        print("You must be root, or sudo, to perform this operation.")

if __name__ == '__main__':
    make_path()
    is_pem = detect_pem()
    pem_file = create_pem_file(is_pem)
    certs = read_certs(pem_file)
    remove(pem_file)
    cert_files = write_certs(certs)

    if args.acas:
        install_certs_acas(cert_files)

    if args.os:
        install_certs_os(cert_files)