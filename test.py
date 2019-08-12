from paddingoracle import PaddingOracle, BadPaddingException
import os
from Crypto.Cipher import AES
import logging
import time

TESTSTRING = 'The quick brown fox jumped over the lazy dog'
GUESS_FRAGMENTS = TESTSTRING.split(' ')


def pkcs7_pad(data, blklen=16):
    if blklen > 255:
        raise ValueError('Illegal block size %d' % (blklen, ))
    pad = (blklen - (len(data) % blklen))
    return data + chr(pad) * pad

class PadBuster(PaddingOracle):
    def __init__(self, key, iv, delay=None):
        super(PadBuster, self).__init__()
        self.key = key
        self.iv = iv
        self.delay = delay

    def oracle(self, data):
        if self.delay is not None:
            time.sleep(self.delay)
    
        _cipher = AES.new(self.key, AES.MODE_CBC, str(self.iv))
        ptext = _cipher.decrypt(str(data))
        plen = ord(ptext[-1])

        padding_is_good = (ptext[-plen:] == chr(plen) * plen)

        if padding_is_good:
            return

        raise BadPaddingException

class GuessingBuster(PadBuster):
    def guess(self, plaintext_after):
        word_after = plaintext_after
        if ' ' in word_after:
            word_after = word_after[:word_after.index(' ')]
            
        for guess in GUESS_FRAGMENTS:
            if guess.endswith(word_after):
                if guess == word_after:
                    # word complete -> space
                    yield ' '
                else:
                    self.log.info("Guessing {0}", guess)
                    yield guess[-len(word_after)-1]

def new_cipher():
    key = os.urandom(AES.block_size)
    iv = bytearray(os.urandom(AES.block_size))
    cipher = AES.new(key, AES.MODE_CBC, str(iv))
    
    return key, iv, cipher

def test():
    logging.basicConfig(level=logging.WARN)

    test_decrypt()
    test_encrypt()
    test_guess()
    test_parallel()

def test_decrypt():
    print "Testing padding oracle exploit in DECRYPT mode"
    
    for _ in xrange(100):
        key, iv, cipher = new_cipher()
        padbuster = PadBuster(key, iv)

        data = pkcs7_pad(TESTSTRING, blklen=AES.block_size)
        ctext = cipher.encrypt(data)

        decrypted = padbuster.decrypt(ctext, block_size=AES.block_size, iv=iv, 
            threads=1)

        assert decrypted == data, \
            'Decrypted data %r does not match original %r' % (
                decrypted, data)

def test_encrypt():
    print "Testing padding oracle exploit in ENCRYPT mode"
    
    for _ in xrange(100):
        key, iv, cipher = new_cipher()
        padbuster = PadBuster(key, iv)
        
        encrypted = padbuster.encrypt(TESTSTRING, block_size=AES.block_size, 
            threads=1)

        decrypted = cipher.decrypt(str(encrypted))[AES.block_size:]
        decrypted = decrypted.rstrip(decrypted[-1])

        assert decrypted == TESTSTRING, \
            'Encrypted data %r does not decrypt to %r, got %r' % (
                encrypted, TESTSTRING, decrypted)


def test_guess():
    print "Testing guessing functionality"
    
    for _ in xrange(100):
        key, iv, cipher = new_cipher()
        padbuster = PadBuster(key, iv)
        guessbuster = GuessingBuster(key, iv)

        data = pkcs7_pad(TESTSTRING, blklen=AES.block_size)
        ctext = cipher.encrypt(data)

        decrypted1 = padbuster.decrypt(ctext, block_size=AES.block_size, iv=iv, 
            threads=1)
        
        decrypted2 = guessbuster.decrypt(ctext, block_size=AES.block_size, 
            iv=iv, threads=1)
        
        assert guessbuster.attempts < padbuster.attempts / 2
        
        assert decrypted1 == data and decrypted2 == data, \
            'Decrypted data do not match original'
            
            
def test_parallel():
    print "Testing multithreaded functionality"
    
    def stopwatch(fnc):
        before = time.time()
        res = fnc()
        return res, time.time() - before

    for _ in xrange(1):
        key, iv, cipher = new_cipher()
        padbuster = PadBuster(key, iv, delay=.02)
        
        data = pkcs7_pad(TESTSTRING, blklen=AES.block_size)
        ctext = cipher.encrypt(data)

        decrypted1, time1 = stopwatch(lambda: padbuster.decrypt(ctext, 
            block_size=AES.block_size, iv=iv, threads=1))
        
        decrypted2, time2 = stopwatch(lambda: padbuster.decrypt(ctext, 
            block_size=AES.block_size, iv=iv, threads=32))
        
        assert time2 < time1
        
        assert decrypted1 == data and decrypted2 == data, \
            'Decrypted data do not match original'

if __name__ == '__main__':
    test()
