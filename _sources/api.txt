.. _api:

Developer Interface
===================

.. module:: paddingoracle

This part of the documentation covers all the interfaces exposed by the
Padding Oracle Exploit API.


Main Interface
--------------

Tool authors should subclass the :class:`PaddingOracle` class and implement :meth:`oracle`.
A typical example may look like::

    from paddingoracle import PaddingOracle, BadPaddingException

    class PadBuster(PaddingOracle):
        def oracle(self, data):

            #
            # code to determine if a padding oracle is revealed
            # if a padding oracle is revealed, raise a BadPaddingException
            #

            raise BadPaddingException

.. autoclass:: PaddingOracle
    :members: decrypt, encrypt, oracle, analyze


Exceptions
----------

.. autoexception:: BadPaddingException
