import numpy as np
from bitstring import Bits


def _byte_array_to_bit_list(arr):
    """Converts a byte array into a list of the corresponding bits

    Example:
        b'123' -> [0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1]

    Args:
        arr (bytes): The bytes to convert

    Returns:
        Numpy array of bits
    """
    length = (len(arr) * 8)
    bitstring = Bits(bytes=arr, length=length)
    return np.array([int(i) for i in list(bitstring)])


def _bit_list_to_byte_array(arr):
    """Converts a list of bits into a bytes object of the corresponding bytes

    Example:
        [0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1] -> b'123'

    Args:
        arr (ndarray): List of bits to convert to bytes

    Returns:
        bytes: the corresponding bytes
    """
    bitstring = ''.join(map(str, map(int, arr)))
    return int(bitstring, 2).to_bytes(len(bitstring) // 8, byteorder='big')


def _perm(msg, p):
    """Permutes the bit array using the provided permutation table

    Expects the both lists to be one dimensional

    Args:
        msg (ndarray): The message bits.
        p (ndarray): The permutation table.

    Returns:
        ndarray: A new list with the bits of msg in the order prescribed by p

    """

    msg_out = np.empty(p.shape, int)
    for i1, i2 in zip(p, range(len(p))):
        msg_out[i2] = msg[i1-1]  # Because the permutation definition from the standard is not zero indexed

    return msg_out


def _xor(arr1, arr2):
    """Computes element wise xor

    Computes element wise xor for each element in the lists and returns a new 
    list containing the results. Expects the lists to be of the same length and
    only contain logical values (True/False/1/0)

    Example:
        a = [0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1]
        b = [1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1]

        _xor(a, b) = _xor(b, a) = [1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0]

    Args:
        arr1 (ndarray): The first list to xor.
        arr2 (ndarray): The second list to xor.

    Returns:
        ndarray: A new list of the same length as arr1 & arr2 containing the result of the xor

    """

    return np.array(list(map(lambda x, y: x ^ y, arr1, arr2)))


def _KS(key):
    """Performs key sampling as described in DES standard

    Accepts a block of 64 bits, performs all necessary operations to produce the 16 sub-keys

    Args:
         key (ndarray): The key to sample

    Returns:
         ndarray: An array of shape (16, 48) where row i is the i:th key

    """
    left_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    pc1 = np.array([
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,

        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ])
    pc2 = np.array([
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ])

    C, D = np.split(_perm(key, pc1), 2)

    keys = []
    for i in range(16):
        C = np.roll(C, -left_shifts[i])
        D = np.roll(D, -left_shifts[i])
        keys.append(_perm(np.concatenate((C, D)), pc2))

    return np.array(keys)


def _S(n, block):
    """Implements the selection function from the DES paper

    Accepts the round and the block (6 bit) for this round and computes the value to retrieve
    from the appropriate S-function as described in the standard. Returns the 4 bytes
    as a list of integers 1/0

    Args:
        n (int): Integer that corresponds to the current round.
        block (ndarray): The key bits for this round as a list of 1/0

    Returns:
        ndarray: The appropriate bits for this round as a list of integers 1/0

    """
    s = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    i = int(str(block[0]) + str(block[5]), 2)
    j = int(''.join(map(str, block[1:5])), 2)

    bin_str = bin(s[n][i][j])[2:]

    return np.array(([0] * (4-len(bin_str))) + list(map(int, bin_str)))


def _E(bits):
    """Implements the E function from the DES paper

    Accepts a block of 32 bits and produces a block of 48 bits

    Args:
        bits (ndarray): The block of 32 bits to expand

    Returns:
        ndarray: The expanded block consisting of 48 bits.

    """
    e = np.array([
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ])

    return _perm(bits, e)


def _P(L):
    """Implements the P function from the DES paper

    Accepts a block of 32 bits and outputs a block of 32 bits, permuted using table P

    Args:
        L (ndarray): The block of 32 bits to permute

    Returns:
        ndarray: The contracted block consisting of 48 bits.

    """
    table = np.array([
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ])

    new_shape = (32, 1)
    return _perm(np.reshape(L, new_shape), table)


def _f(R, K):
    """The f function from the DES paper

    It accepts a 32 bit block to encrypt and a 48 bit key to use for encryption

    Args:
        R (ndarray): The block to encrypt (32 bit).
        K (ndarray): The key to use in encryption (48 bit).

    Returns:
        ndarray: a permuted version of R (32 bit)

    """
    blocks = np.split(_xor(K, _E(R)), 8)
    L = [_S(i, block) for block, i in zip(blocks, range(len(blocks)))]
    return _P(L)


def _round(key, message):
    """Performs an encryption round of the DES algorithm

    Accepts an entire 64 bit block and performs an encryption round on the block

    Args:
        key (ndarray): A 48 bit key to use in this round.
        message (ndarray): A 64 bit message to encrypt.

    Returns:
        ndarray: the encrypted message (64 bit).

    """
    # pylint: disable=unbalanced-tuple-unpacking
    L0, R0 = np.split(message, 2)
    L1 = R0
    R1 = _xor(L0, _f(R0, key))
    return np.concatenate((L1, R1))


def _encrypt_block(key_n, block):
    """Performs the complete encryption of a block using the provided keys

    Accepts the 16 key samples to use when performing the 16 rounds of encryption of the block.
    This function performs all necessary operations to completely encrypt the provided block.

    Args:
        key_n (ndarray): List of shape (16, 48) containing the different keys to use for each round
        block (ndarray): 64 bit block to encrypt

    Returns:
        ndarray: The encrypted block (64 bits)

    """
    block = _perm(block, __ip)

    for key in key_n:
        block = _round(key, block)

    L, R = np.split(block, 2)
    swapped = np.concatenate((R, L))
    return _perm(swapped, __ip_inv)


def _pad(block, n=8):
    """Pads the block to a multiple of n

    Accepts an arbitrary sized block and pads it to be a multiple of n.
    Padding is done using the PKCS5 method, i.e., the block is padded with
    the same byte as the number of bytes to add.

    Args:
        block (bytes): The block to pad, may be arbitrary large.
        n (int): The resulting bytes object will be padded to a multiple of this number

    Returns:
        bytes: a bytes object created from the input string

    """
    if len(block) % n == 0:
        return block

    pad_len = n - (len(block) % n)
    block += bytes([pad_len] * pad_len)
    return block


def __make_sure_bytes(input_str):
    """Makes sure that the input string is of type bytes

    Tries to convert type to byte and throws an error if that is not possible

    Args:
        input_str (bytes): The input string to validate.

    Returns:
        bytes: a bytes object created from the input string

    """
    if not isinstance(input_str, bytes):
        raise TypeError('Argument must be of type string or bytes')


def __enforce_key_length(block):
    if len(block) % 8 != 0:
        raise ValueError('Expected key to be exactly 8 bytes, got {}'.format(len(block)))


__ip = np.array([
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
])

__ip_inv = np.array([
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
])


def encrypt(block, key):
    """Encrypts the provided block using the provided key

    Accepts the block to encrypt as well as the key to use. Both of which MUST be exactly 8 bytes long and
    of type bytes. Will not do a parity bit check of the key.

    Args:
        block (bytes): The input string to validate.
        key (bytes): The key to use for encryption.

    Returns:
        bytes: The block encrypted with the provided key.

    """
    __make_sure_bytes(block)
    __make_sure_bytes(key)

    __enforce_key_length(key)
    key = _byte_array_to_bit_list(key)
    key_n = _KS(key)

    bits = _byte_array_to_bit_list(_pad(block))
    blocks = np.split(bits, int(len(bits) / 64))

    encrypted_blocks = [_encrypt_block(key_n, block) for block in blocks]

    return _bit_list_to_byte_array(np.concatenate(encrypted_blocks))


