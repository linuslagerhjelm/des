# DES
An implementation of the Data Encryption Standard (DES) written in
pure python with a minimal amount of dependencies. 

This is mostly written for educational purposes; however, should you need a pure python implementation for whatever reason, this should be correct enough so feel free to go ahead and use it. 

Of course DES is no longer considered secure, even when implemented correctly, so do not use it for anything important. 

__Example usage:__

```python
import des

string = b'abcdefgh'
cipher_text = des.encrypt(string * 2, key=b'descrypt', iv=b'+\x8c\x17\xcf-\xe0k>')

print(cipher_text)  # b'w\xb8d\xbc\xa9 B\xd9\x15\x7f\x1e_\xa4\xcbs\xd10?!>\xc4\xc4&\x95'
```

__Planned features:__

 - ~~CBC mode~~
 - ~~PKCS5 padding~~
 - ~~Decryption~~
 - HMAC
---
 - Tripple DES
