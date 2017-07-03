#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
 Copyright (C) 2016 Eleven Paths
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.
 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.
 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import re
import hashlib
import os
import subprocess
import requests
import sys
import json
import config
import math
import ecdsa
import argparse

from OpenSSL import crypto

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from ecdsa import VerifyingKey
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def _write_uint(value, num_bytes, buf):
    int_bytes = bytearray()
    for _ in range(num_bytes):
        int_bytes.append(value & 0xff)
        value >>= 8
    int_bytes.reverse()
    buf.extend(int_bytes)


def _write_bounded_uint(value, max_value, buf):
    length_of_value = int(math.ceil(math.log(max_value, 2)))
    _write_uint(value, length_of_value, buf)


def _write_var_bytes(value, max_length, buf):
    _write_bounded_uint(len(value), max_length, buf)
    buf.extend(value)


def _read_fixed_bytes(num_bytes, buf):
    global pos
    ret = buf[pos:pos + num_bytes]
    pos += num_bytes
    return ret


def _read_uint(num_bytes, buf):
    int_bytes = bytearray(_read_fixed_bytes(num_bytes, buf))
    ret = 0
    for b in int_bytes:
        ret <<= 8
        ret += b
    return ret


def _read_bounded_uint(max_value, buf):
    length_of_value = int(math.ceil(math.log(max_value + 1, 2)))
    value = _read_uint(length_of_value, buf)

    return value


def _read_var_bytes(max_length, buf):
    length = _read_bounded_uint(max_length, buf)
    return _read_fixed_bytes(length, buf)


def set_pos(value):
    global pos
    pos = value


def extract_sct_info(sct_raw, sct_version, sct_log, sct_timestamp, sct_extensions, sct_signature_type, sct_signature, sct_type, type):
    global pos
    if type != 'ocsp':
        pos = 4
        sct_sequence = _read_var_bytes(2, sct_raw)
    else:
        pos = 1
        length = _read_fixed_bytes(1, sct_raw).encode('hex')
        if int(length[0],16) < 8:
            bytes_to_read = int(length, 16)
            sct_sequence = _read_fixed_bytes(bytes_to_read, sct_raw)
        else:
            sct_sequence = _read_var_bytes(int(length[1], 16), sct_raw)
            pos = 0
            sct_sequence = _read_var_bytes(2, sct_sequence)
    pos = 0
    sct = []
    while pos < len(sct_sequence):
        sct.append(_read_var_bytes(2, sct_sequence))

    for singleSCT in sct:
        pos = 0
        sct_version.append(_read_fixed_bytes(1, singleSCT))
        sct_log.append(_read_fixed_bytes(32, singleSCT))
        sct_timestamp.append(_read_fixed_bytes(8, singleSCT))
        sct_extensions.append(_read_fixed_bytes(2, singleSCT))
        sct_signature_type.append(_read_fixed_bytes(2, singleSCT))
        sct_signature.append(_read_var_bytes(2, singleSCT))
        sct_type.append(type)
    return len(sct)


def _check_host_sct(host_name):

    logs_list_json = requests.get(config.CT_LOGS_LIST)
    logs = {}

    try:
        logs_aux = logs_list_json.json().get('logs')

        for l in logs_aux:

            log_id = hashlib.sha256(l.get('key').decode('base64')).digest().encode('base64').replace('\n', '')

            entry = {'url': 'https://' + l.get('url'),
                     'key': l.get('key'),
                     'log_name': l.get('description')}

            logs.update({log_id: entry})

    except ValueError as e:
        print "Error at logs list updating, using default list instead.\n\tError details: " + repr(e)

        with open('logs_data.json', 'r') as ld:
            logs = json.load(ld)

    host_name = host_name
    continue_exec = True

    global pos
    pos = 0

    sct_version = []
    sct_log = []
    sct_timestamp = []
    sct_extensions = []
    sct_signature_type = []
    sct_signature = []
    sct_type = []
    sct_number = 0
    precert_exists = False

    try:
        print "\n** Connecting to host: " + host_name + "... **\n"

        # TODO: Replace os.popen by subprocess or directly use Python code instead openssl (e.g. M2Crypto).
        tmp = os.popen("openssl s_client -showcerts -servername " + host_name + " -connect " + host_name + ":443 </dev/null 2>&1").read()

        begin_cert_str = '-----BEGIN CERTIFICATE-----'
        end_cert_str = '-----END CERTIFICATE-----'
        begin_cert_index = tmp.index(begin_cert_str)
        end_cert_index = tmp.index(end_cert_str)
        certificate_pem = tmp[begin_cert_index + len(begin_cert_str):end_cert_index]

        issuer_pem = tmp[end_cert_index + len(end_cert_str):]
        begin_cert_index = issuer_pem.index(begin_cert_str)
        end_cert_index = issuer_pem.index(end_cert_str)
        issuer_pem = issuer_pem[begin_cert_index + len(begin_cert_str):end_cert_index]

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, begin_cert_str+certificate_pem+end_cert_str)

        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert=cert)

    except Exception as e:
        print "Error: Certificate not found for host " + host_name
        continue_exec = False

    if continue_exec:

        print "\n** Looking for embedded SCT in certificate **"

        type = ""

        for i in range(cert.get_extension_count()):

            if cert.get_extension(i).get_short_name() == 'ct_precert_scts':
                sct_raw_precert = bytearray()
                sct_raw_precert = cert.get_extension(i).get_data()
                type = "precert"

        if type == "precert":
            precert_exists = True
            sct_number += extract_sct_info(sct_raw_precert, sct_version, sct_log, sct_timestamp, sct_extensions, sct_signature_type,
                                           sct_signature, sct_type, type)
        else:
            print "\t> No embedded sct found on host's certificate"
            # NO SCT

        try:
            print "\n** Looking for SCTs in TLS extensions**"

            try:
                openssl_path = os.environ["OPENSSL_PATH"]
            except:
                openssl_path = "openssl"

            Args = [openssl_path]
            Args.extend(["s_client", "-serverinfo", "18", "-connect", "%s:443" % host_name, "-servername", host_name])

            openssl_process = subprocess.Popen(Args, stdin=open('/dev/null', 'r'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            openssl_process_stdout, OpenSSL_stderr = openssl_process.communicate()
            openssl_process_exitcode = openssl_process.wait()

            if openssl_process_exitcode != 0:
                print("Error: OpenSSL can't connect to %s" % host_name)
                print("\tError details" + OpenSSL_stderr)
            begin_cert_str_ext18 = '-----BEGIN SERVERINFO FOR EXTENSION 18-----'
            end_cert_str_ext18 = '-----END SERVERINFO FOR EXTENSION 18-----'
            begin_cert_index = openssl_process_stdout.index(begin_cert_str_ext18)
            end_cert_index = openssl_process_stdout.index(end_cert_str_ext18)
            sct_raw_tls = bytearray()
            sct_raw_tls = openssl_process_stdout[begin_cert_index + len(begin_cert_str_ext18):end_cert_index].decode('base64')

            type = "tls"
            sct_number += extract_sct_info(sct_raw_tls, sct_version, sct_log, sct_timestamp, sct_extensions, sct_signature_type,
                                           sct_signature, sct_type, type)
        except:
            # NO TLS
            print "\t> No sct found on TLS"

        cert_aux_filename = host_name + ".pem"

        if not os.path.exists('tmp'):
            os.makedirs('tmp')

        try:

            print "\n** Looking for SCTs in OCSP response **"

            command = "openssl s_client -connect " + host_name + ":443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' | cat > tmp/" + cert_aux_filename
            tmp = os.popen(command).read()

            command = "openssl s_client -connect " + host_name + ":443 2>&1 -showcerts < /dev/null | sed -n '/-----BEGIN/,/-----END/p' | perl -0777 -pe 's/.*?-{5}END\sCERTIFICATE-{5}\n//s' | cat > tmp/chain_" + cert_aux_filename
            tmp = os.popen(command).read()

            command = "openssl x509 -noout -ocsp_uri -in tmp/" + cert_aux_filename
            tmp = os.popen(command).read()
            m = re.search('http://(.+?)\n', tmp)

            if m is not None:
                print "\t> OCSP address not found"
                # TODO: Don't continue execution

            ocsp_url = m.group(1).replace('\n', '')

            command = "openssl ocsp -issuer tmp/chain_" + cert_aux_filename + " -cert tmp/" + cert_aux_filename \
                + " -respout tmp/" + cert_aux_filename + ".tmp -url http://" + ocsp_url \
                + " -header HOST " + ocsp_url + " -VAfile tmp/chain_" + cert_aux_filename + "2>&1"
            tmp = os.popen(command).read()

            with open('tmp/' + cert_aux_filename + ".tmp", mode='rb') as file:  # b is important -> binary
                sct_raw_ocsp = file.read()

            start_sct = sct_raw_ocsp.encode('hex').index('060a2b06010401d679020405')+len('060a2b06010401d679020405')
            sct_raw_ocsp = sct_raw_ocsp.encode('hex')[start_sct:].decode('hex')
            pos = 1
            length = _read_fixed_bytes(1, sct_raw_ocsp).encode('hex')
            if length[0] < 8:
                bytes_to_read = int(length, 16)
                sct_raw_ocsp = _read_fixed_bytes(bytes_to_read, sct_raw_ocsp)
            else:
                sct_raw_ocsp = _read_var_bytes(int(length[1], 16), sct_raw_ocsp)

            type="ocsp"
            sct_number += extract_sct_info(sct_raw_ocsp, sct_version, sct_log, sct_timestamp, sct_extensions, sct_signature_type,
                                           sct_signature, sct_type, type)
        except Exception as e:
            # NO OCSP
            print "\t> No sct found in OCSP response"

        finally:
            if os.path.exists('tmp/' + cert_aux_filename + '.tmp'):
                os.remove('tmp/' + cert_aux_filename + '.tmp')

            if os.path.exists('tmp/chain_' + cert_aux_filename):
                os.remove('tmp/chain_' + cert_aux_filename)

            if os.path.exists('tmp/' + cert_aux_filename):
                os.remove('tmp/' + cert_aux_filename)

        if precert_exists:
            issuer = crypto.load_certificate(crypto.FILETYPE_PEM, begin_cert_str+issuer_pem+end_cert_str)
            issuer_public_key = issuer.get_pubkey().to_cryptography_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            m = hashlib.sha256()
            m.update(issuer_public_key)
            issuer_public_key = m.digest()

        tbs = bytearray()

        pos = 1
        length = _read_fixed_bytes(1, cert_der).encode('hex')
        if int(length[0], 16) < 8:
            pos += 2
        else:
            pos += int(length[1], 16) + 1

        length = _read_fixed_bytes(1, cert_der).encode('hex')
        if int(length[0],16) < 8:
            tbs_hex = _read_fixed_bytes(int(length, 16), cert_der).encode('hex')
        else:
            tbs_hex = _read_var_bytes(int(length[1], 16), cert_der).encode('hex')

        if precert_exists:
            sct_sequence_hex = sct_raw_precert.encode('hex')
            length = hex(len(sct_raw_precert)).replace('0x', '') \
                if len(hex(len(sct_raw_precert)).replace('0x', '')) % 2 == 0 \
                else '0'+hex(len(sct_raw_precert)).replace('0x', '')

            sct_sequence_hex = '060a2b06010401d679020402048' + str(len(length) / 2) + length + sct_sequence_hex
            length = hex(len(sct_sequence_hex.decode('hex'))).replace('0x', '') \
                if len(hex(len(sct_sequence_hex.decode('hex'))).replace('0x', '')) % 2 == 0 \
                else '0' + hex(len(sct_sequence_hex.decode('hex'))).replace('0x', '')

            sct_sequence_hex = '308' + str(len(length) / 2) + length + sct_sequence_hex

            tbs = tbs_hex.decode('hex')
            pos = 1
            # Skip Version
            _read_var_bytes(1, tbs)
            pos += 1
            # Skip Fingerprint
            _read_var_bytes(1, tbs)
            pos += 1
            # Skip signature type
            _read_var_bytes(1, tbs)
            pos += 1
            # Skip Issuer
            length = _read_fixed_bytes(1, tbs).encode('hex')
            if int(length[0], 16) < 8:
                _read_fixed_bytes(int(length, 16), tbs)
            else:
                _read_var_bytes(int(length[1], 16), tbs)
            pos += 1
            # Skip Valid date
            _read_var_bytes(1, tbs)

            pos += 1
            # Skip Subject
            length = _read_fixed_bytes(1, tbs).encode('hex')
            if int(length[0], 16) < 8:
                _read_fixed_bytes(int(length, 16), tbs)
            else:
                _read_var_bytes(int(length[1], 16), tbs)

            pos += 1
            # Skip RSA encryption
            length = _read_fixed_bytes(1, tbs).encode('hex')
            if int(length[0], 16) < 8:
                _read_fixed_bytes(int(length, 16), tbs)
            else:
                _read_var_bytes(int(length[1], 16), tbs)

            original_extensions_hex = tbs[pos:].encode('hex')

            pos += 1
            # Skip Sequence tag
            length = _read_fixed_bytes(1, tbs).encode('hex')
            if int(length[0], 16) < 8:
                pos += 1
            else:
                pos += 2

            pos += 1
            # Skip Sequence tag
            length = _read_fixed_bytes(1, tbs).encode('hex')
            if int(length[0], 16) < 8:
                pos += 1
            else:
                pos += 2

            extensions_hex = tbs[pos:].encode('hex')
            extensions_hex = extensions_hex.replace(sct_sequence_hex, '')
            extensions = extensions_hex.decode('hex')
            length = hex(len(extensions)).replace('0x', '') \
                if len(hex(len(extensions)).replace('0x', '')) % 2 == 0 \
                else '0' + hex(len(extensions)).replace('0x', '')

            extensions_hex = '308' + str(len(length) / 2) + length + extensions_hex
            length = hex(len(extensions_hex.decode('hex'))).replace('0x', '') \
                if len(hex(len(extensions_hex.decode('hex'))).replace('0x', '')) % 2 == 0 \
                else '0' + hex(len(extensions_hex.decode('hex'))).replace('0x', '')

            extensions_hex = 'a38' + str(len(length) / 2) + length + extensions_hex

            tbs_hex = tbs_hex.replace(original_extensions_hex,extensions_hex)
            tbs = tbs_hex.decode('hex')
            length = hex(len(tbs)).replace('0x', '') \
                if len(hex(len(tbs)).replace('0x', '')) % 2 == 0 \
                else '0' + hex(len(tbs)).replace('0x', '')

            tbs_hex = '308' + str(len(length) / 2) + length + tbs_hex
            tbs = tbs_hex.decode('hex')

        print "\n** Logs detected in SCTs **"

        for i in range(sct_number):

            log_id = sct_log[i].encode('base64').replace('\n', '')

            log = logs.get(log_id)

            if log is not None:

                log_name = log.get('log_name')

                print "\t> " + log_name + " (" + sct_type[i] + ")"

                try:
                    if sct_type[i] == "precert":
                        length = hex(len(tbs)).replace('0x', '') if len(hex(len(tbs)).replace('0x', '')) % 2 == 0 else '0' + hex(
                            len(tbs)).replace('0x', '')
                        message = sct_version[i] + '00'.decode('hex') + sct_timestamp[i] + '0001'.decode('hex') + issuer_public_key +\
                                  '00'.decode('hex') + length.decode('hex') + tbs + sct_extensions[i]
                    else:
                        length = hex(len(cert_der)).replace('0x', '') if len(
                            hex(len(cert_der)).replace('0x', '')) % 2 == 0 else '0' + hex(
                            len(cert_der)).replace('0x', '')
                        message = sct_version[i] + '00'.decode('hex') + sct_timestamp[i] + '0000'.decode('hex') + \
                                  '00'.decode('hex') + length.decode('hex') + cert_der + sct_extensions[i]

                    public_key = log.get('key')

                    verified_signature = False

                    if sct_signature_type[i].encode('hex') == '0403':
                        pub = VerifyingKey.from_der(public_key.decode('base64'))
                        verified_signature = pub.verify(sct_signature[i], message, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)
                    else:
                        rsakey = RSA.importKey(public_key.decode('base64'))
                        signer = PKCS1_v1_5.new(rsakey)
                        digest = SHA256.new()
                        digest.update(message)
                        verified_signature = signer.verify(digest, sct_signature[i])

                    print "\t\t└─ Verified signature: " + str(verified_signature) + "\n"
                except Exception as e:
                    print "Error occurred with log " + log_name + "\n\tError details: " + repr(e)
            else:
                print "\t> Unknown log"

if __name__ == '__main__':
 
    print "\nPySCTChecker (c) ElevenPaths. Version: 0.1.0.0\n"
    parser = argparse.ArgumentParser(description="Checks Certificate Transparency for the introduced domain list.")
    parser.add_argument('domains', type=str, nargs='+', help='Domain list to check CT')
    args = parser.parse_args()

    for domain in args.domains:
        print "__________________________________________________________________________"
        print " DOMAIN: " + domain
        print "--------------------------------------------------------------------------"
        _check_host_sct(domain)
        print "\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"

