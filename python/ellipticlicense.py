#
#  ellipticlicense.py
#  EllipticLicense
#
#  Copyirght (c) 2016 Vaclav Slavik
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import importlib.util
from ctypes import CDLL, c_void_p, byref, create_string_buffer

_impl = CDLL(importlib.util.find_spec('_ellipticlicense').origin)
_impl.el_create_context.restype = c_void_p

# Supported elliptic curves
SECP112R1 = 112
SECP128R1 = 128
SECP160R1 = 160


class LicenseVerifier:
    """
    Verifies validity of licenses.
    """
    def __init__(self, curve, public_key):
        """

        :param curve: Elliptic curve to use, one of the SECPxxx constants
        :param public_key: A bytearray with the public key
        """
        self.ctxt = c_void_p(_impl.el_create_context(curve, public_key, len(public_key)))
        self._blocked_keys_data = None

    def __del__(self):
        if self.ctxt:
            _impl.el_destroy_context(self.ctxt)

    def set_blocked_keys(self, data):
        """
        Sets list of blocked (blacklisted) keys that should not be accepted.

        Typically, this functionality is used to block keys for refunded purchases
        or pirated keys so that they aren't recognized as valid anymore.

        The data bytearray contains SHA-1 hashes of blocked keys (20 bytes per
        hash). The hashes are computed from license keys (not names) by first
        decoding the user-entered key as base32 and then calculating SHA-1 hash
        of the decoded data.

        :param data: bytearray with hashes of blocked keys
        """
        # must be kept around, because el_set_blocked_keys() doesn't make a copy
        self._blocked_keys_data = create_string_buffer(data)
        _impl.el_set_blocked_keys(byref(self._blocked_keys_data), len(data))

    def verify_license_key(self, key, name):
        """
        Verifies that the license key associated with 'name' is valid.

        :param key: The key, as a base32-encoded string.
        :param name: Identifier of license holder (e.g. name), as a string or UTF-8 encoded bytearray.
        :return: True if the key is valid, False otherwise.
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(name, str):
            name = name.encode('utf-8')
        return bool(_impl.el_verify_license_key(self.ctxt, key, name))


class LicenseGenerator:
    """
    Generates licenses.
    """
    def __init__(self, curve, public_key, private_key):
        """
        :param curve: Elliptic curve to use, one of the SECPxxx constants
        :param public_key: A bytearray with the public key
        :param private_key: A bytearray with the private key
        """
        self.ctxt = c_void_p(_impl.el_create_context(curve, public_key, len(public_key)))
        if not bool(_impl.el_set_private_key(self.ctxt, private_key, len(private_key))):
            raise RuntimeError('invalid private key')

    def __del__(self):
        if self.ctxt:
            _impl.el_destroy_context(self.ctxt)

    def generate_license_key(self, name):
        """
        Generates a new license key for 'name'.

        :param name: Identifier of license holder (e.g. name), as a string or UTF-8 encoded bytearray.
        :return: String with the license key.
        """
        if isinstance(name, str):
            name = name.encode('utf-8')
        size = _impl.el_generate_license_key(self.ctxt, name, None)
        buf = create_string_buffer(size)
        if _impl.el_generate_license_key(self.ctxt, name, byref(buf)) == -1:
            raise RuntimeError('error generating license key')
        return buf.value.decode('utf-8')

