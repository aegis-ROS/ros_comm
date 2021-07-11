class Encrypt():
    def __init__(self):
        self.encryption_level = -1
        self.encryption_type = None
        self.__key = ''

    def get_enclipt_type(self):
        pass

    def set_enclipt_level(self, level: int):
        self.encryption_level = level

    def set_encryption_type(self, enc_type: 'str'):
        self.encryption_type = enc_type
        if self.encryption_type == 'XOR':
            self.encryption = XOR(self.__key)
        elif self.encryption_type == 'RSA':
            self.encryption = RSA(self.__key)
        elif self.encryption_type == 'AES':
            self.encryption = AES(self.__key)
        elif not self.encryption_type:
            self.encryption = BaseEncryption('')
        else:
            raise Exception('Unknown encryption type fuck you :middle finger:')

    def set_key(self, key: str):
        self.__key = key

    def enc(self, plain_message):
        if not self.encryption:
            raise Exception('Not prepared')
        return self.encryption.enc(plain_message)

    def dec(self, cipher_message):
        if not self.encryption:
            raise Exception('Not prepared')
        return self.encryption.dec(cipher_message)

class BaseEncryption():
    def __init__(self, key):
        self.key = key

    def enc(self, plain_message):
        '''
        interface of enc()
        arg
            plain_message: str original message
        return
            cipher_message: str cipher text
        '''
        return plain_message

    def dec(self, cipher_message):
        '''
        interface of dec()
        arg
            cipher_message: str cipher text
        return
            plain_message: str original message
        '''
        return cipher_message

class XOR(BaseEncryption):
    def __init__(self, key):
        super().__init__(key)

    def enc(self, plain_message):
        return ''.join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(plain_message, self.key)])

    def dec(self, cipher_message):
        return ''.join([chr(ord(c1) ^ ord(c2)) for (c1,c2) in zip(cipher_message, self.key)])

class RSA(BaseEncryption):
    pass

class AES(BaseEncryption):
    pass