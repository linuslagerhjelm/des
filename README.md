# DES
A performant implementation of the Data Encryption Standard (DES) written in
pure python with a minimal amount of dependencies. 

Currently, the algorithm only support encryption using ECB mode. 
However, support for CBC as well as padding is planned for the future.

__Example usage:__

```python
import des

cipher_text = des.encrypt(b'abcdefgh', key=b'descrypt')

print(cipher_text)  # b'\x03<\xb4\xd8E\xd98\xa7'
```

__Planned features:__

 - CBC mode
 - ~~PKCS5 padding~~
 - Decryption
---
 - Tripple DES