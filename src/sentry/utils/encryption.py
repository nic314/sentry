from __future__ import absolute_import

import six

from collections import OrderedDict
from django.conf import settings
from django.utils.encoding import smart_bytes


class EncryptionManager(object):
    def __init__(self, schemes=()):
        for key, value in schemes:
            if not isinstance(key, six.string_types):
                raise ValueError('Encryption scheme type must be a string. Value was: {!r}'.format(value))
            if not hasattr(value, 'encrypt') or not hasattr(value, 'decrypt'):
                raise ValueError('Encryption scheme value must have \'encrypt\' and \'decrypt\' callables. Value was: {!r}'.format(value))
        self.schemes = OrderedDict(schemes)
        if not schemes:
            self.default_scheme = None
        else:
            self.default_scheme = schemes[0][0]

    def encrypt(self, value):
        if self.default_scheme is None:
            return value
        value = smart_bytes(value)
        scheme = self.schemes[self.default_scheme]
        return b'\x00{}${}'.format(self.default_scheme, scheme.encrypt(value))

    def decrypt(self, value):
        # we assume that if encryption is not configured, it was never
        # configured
        if not self.schemes:
            return value
        if not value.startswith(b'\x00'):
            return value
        try:
            enc_method, enc_data = value[1:].split('$', 1)
        except (ValueError, IndexError):
            return value
        if not enc_method:
            return value
        enc_data = smart_bytes(enc_data)
        try:
            scheme = self.schemes[enc_method]
        except KeyError:
            raise ValueError('Unknown encryption scheme: {!r}'.format(enc_method))
        return scheme.decrypt(enc_data)

default_manager = EncryptionManager(settings.SENTRY_ENCRYPTION_SCHEMES)

encrypt = default_manager.encrypt
decrypt = default_manager.decrypt
