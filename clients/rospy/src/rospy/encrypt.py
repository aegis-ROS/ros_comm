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
    # "pythonでXORプチ暗号化 - Qiita", https://qiita.com/magiclib/items/fe2c4b2c4a07e039b905, (参照2021-07-26)
    def __init__(self, key):
        super().__init__(key)

    def enc(self, plain_message):
        if plain_message and self.key:
            xor_code = self.key
        # keyが短い場合は、繰り返して必要バイト数を準備する
        while len(plain_message) > len(xor_code):
            xor_code += self.key
        return "".join([chr(ord(data) ^ ord(code))
                        for (data, code) in zip(plain_message, xor_code)]).encode().hex()


    def dec(self, cipher_message):
        if cipher_message and self.key:
            try:
                crypt_data = bytes.fromhex(cipher_message).decode()
            except ValueError:
                crypt_data = None

            if crypt_data:
                xor_code = self.key
                # keyが短い場合は、繰り返して必要バイト数を準備する
                while len(crypt_data) > len(xor_code):
                    xor_code += self.key
                return "".join([chr(ord(data) ^ ord(code))
                                for (data, code) in zip(crypt_data, xor_code)])

class RSA(BaseEncryption):
    pass

class AES(BaseEncryption):
    pass