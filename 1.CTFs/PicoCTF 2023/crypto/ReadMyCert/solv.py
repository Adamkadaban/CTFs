import os
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

def get_csr_file(csr_file=None):
    if csr_file is None or not os.path.exists(csr_file):
        return None
    with open(csr_file, 'r') as crt:
        return crt.read()


def get_csr_data(file=None):
    csr = get_csr_file(file)
    if csr is None:
        return None
    csr_request = load_certificate_request(FILETYPE_PEM, csr)
    pub_key = csr_request.get_pubkey()
    pub_key_type = 'RSA' if pub_key.type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
    pub_key_size = pub_key.bits()
    subject = csr_request.get_subject()
    components = dict(subject.get_components())
    return {
        'key_type': pub_key_type,
        'key_size': pub_key_size,
        'attributes': components
    }

print(get_csr_data('readmycert.csr'))
