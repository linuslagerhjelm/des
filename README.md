# DES
A performant implementation of the Data Encryption Standard (DES) written in
pure python with a minimal amount of dependencies. 

Currently, the algorithm only support encryption of one block at the time and
does not support padding. However, support for both ECB, CBC as well as padding
is planned for the future.

*Example usage:*

```python
des.encrypt(b'abcdefgh', b'descrypt')  # b'\x03<\xb4\xd8E\xd98\xa7'
```
