"""
Description: Python 3 script help with custom ChaCha20 decoding as seen in use by APT41
Author: @BitsOfBinary

License:
Copyright 2021 PwC UK

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from Crypto.Cipher import ChaCha20

def ChaCha20_Custom(key: bytes, nonce: bytes, counter: int, ciphertext: bytes) -> bytes:
    ciphertext = b"\x00"*(counter * 64) + ciphertext

    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext[(counter * 64):]