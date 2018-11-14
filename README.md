# DES
An implementation of the Data Encryption Standard (DES) written in
pure python with a minimal amount of dependencies. 

This is mostly written for educational purposes; however, should you need a pure python implementation for whatever reason, this should be correct enough so feel free to go ahead and use it. Of course DES is no longer considered secure, even when implemented correctly, so do not use it for anything important. 

__Example usage:__

```python
import des

cipher_text = des.encrypt(b'abcdefgh', key=b'descrypt', mode='ECB')

print(cipher_text)  # b'\x03<\xb4\xd8E\xd98\xa7'
```

__Planned features:__

 - ~~CBC mode~~
 - ~~PKCS5 padding~~
 - Decryption
---
 - Tripple DES
