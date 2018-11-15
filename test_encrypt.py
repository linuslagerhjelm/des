from unittest import TestCase

import base64
import numpy as np
import des

STR = b'linuslag'
KEY = b'descrypt'


class TestEncrypt(TestCase):
    def test_sunny_day_encryption(self):
        expected = 'MnXbEuUtI54='
        actual = base64.b64encode(des.encrypt(STR, KEY, 'ECB')).decode('ascii')
        self.assertEqual(expected, actual)

    def test_encrypt_multiple_blocks(self):
        expected = 'MnXbEuUtI54yddsS5S0jng=='
        actual = base64.b64encode(des.encrypt(STR * 2, KEY, 'ECB')).decode('ascii')
        self.assertEqual(expected, actual)

    def test_pad_last_block_pkcs5(self):
        expected = 'MnXbEuUtI5576qKp8Cd5Ag=='
        actual = base64.b64encode(des.encrypt(b'linuslagl', KEY, 'ECB')).decode('ascii')
        self.assertEqual(expected, actual)

    def test_pad_single_block_pkcs5(self):
        expected = 'e+qiqfAneQI='
        actual = base64.b64encode(des.encrypt(b'l', KEY, 'ECB')).decode('ascii')
        self.assertEqual(expected, actual)

    def test_numeric_input(self):
        with self.assertRaises(TypeError):
            des.encrypt(1, 2, 'ECB')

    def test_wrong_length(self):
        with self.assertRaises(ValueError):
            des.encrypt(b'a', b'b', 'ECB')

    def test_string_to_bit_list(self):
        expected = [0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1,
                    0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0]
        actual = des._byte_array_to_bit_list(KEY).tolist()
        self.assertEqual(expected, actual)

    def test_bit_list_to_string(self):
        expected = KEY
        actual = des._bit_list_to_byte_array(des._byte_array_to_bit_list(KEY))
        self.assertEqual(expected, actual)

    def test_perm(self):
        p1 = np.array([1, 2, 3, 4])
        p2 = np.array([2, 3, 4, 1])
        self.assertEqual(p2.tolist(), des._perm(p1, p2).tolist())

    def test_xor(self):
        a1 = [1, 0, 1, 0]
        a2 = [1, 1, 1, 1]
        self.assertEqual([0, 1, 0, 1], des._xor(a1, a2).tolist())

    def test_select(self):
        n = 0
        a = np.ones(6, int)
        self.assertEqual([1, 1, 0, 1], des._S(n, a).tolist())

    def test_select_real(self):
        inp = np.array([1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0,
                        0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1])
        expected = [0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1]
        actual = []
        for i, b in zip(range(8), np.reshape(inp, (8, 6))):
            actual.extend(des._S(i, b))
        self.assertEqual(expected, actual)

    def test_e_function(self):
        in_arr = np.array([1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
                           1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1])
        out = np.array([1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1,
                        1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1])

        self.assertEqual(out.tolist(), des._E(in_arr).tolist())

    def test_p_function(self):
        in_array = np.array([0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1,
                             0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1])
        expect = np.array([1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1,
                           0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0])

        self.assertEqual(expect.tolist(), des._P(in_array).tolist())

    def test_KS(self):
        keys = [
            [
                1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
                1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
                0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1
            ],
            [
                1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
                1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
                0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1
            ],
            [
                1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0,
                0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1,
                0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0
            ],
            [
                1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1,
                0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0,
                0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            [
                1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
                0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0
            ],
            [
                1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1,
                0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0,
                1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0
            ],
            [
                1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1,
                1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0,
                0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1
            ],
            [
                1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1,
                1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1,
                1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0
            ],
            [
                0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1,
                1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0,
                0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1
            ],
            [
                0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1,
                1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0,
                0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            [
                0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1,
                1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0
            ],
            [
                0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1,
                1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1,
                1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0
            ],
            [
                1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1,
                1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0,
                0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0
            ],
            [
                1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0,
                1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0
            ],
            [
                1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0,
                1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
            ],
            [
                1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0,
                1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,
                0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1
            ]
        ]
        actual_bits = des._KS(des._byte_array_to_bit_list(KEY))

        [self.assertEqual(expected, actual.tolist()) for expected, actual in zip(keys, actual_bits)]

    def test_round(self):
        key = np.array([1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
                        0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1])
        message = np.array([1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1,
                            0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0,
                            0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0])
        expected = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1,
                    0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1,
                    0, 1, 0, 1, 1, 0, 0, 0]

        actual = des._round(key, message).tolist()

        self.assertEqual(expected, actual)

    def test_f_function(self):
        R = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
                      1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0])
        K = np.array([1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1,
                      1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
                      0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1])
        expected = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0]

        self.assertEqual(expected, des._f(R, K).tolist())

    def test_invalid_iv(self):
        with self.assertRaises(ValueError):
            des.encrypt(STR, KEY, 'CBC', iv=b'\0')

    def test_iv_not_provided(self):
        with self.assertRaises(TypeError):
            des.encrypt(STR, KEY, 'CBC')

    def test_cbc_mode_single_block(self):
        expected = 'MnXbEuUtI54='
        actual = base64.b64encode(des.encrypt(STR, KEY, 'ECB')).decode('ascii')

        self.assertEqual(expected, actual)

    def test_cbc_mode_multiple_blocks(self):
        expected = b'2u\xdb\x12\xe5-#\x9e\xe7\x8b\x99\x85M\xcc\x9a\r'
        actual = des.encrypt(STR * 2, KEY, iv=b'\0\0\0\0\0\0\0\0')

        self.assertEqual(expected, actual)
