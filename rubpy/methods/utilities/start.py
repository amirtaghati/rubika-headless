from ... import exceptions
from ...crypto import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class Start:
    async def start(self, phone_number: str = None, phone_code: str = None, pass_key: str = None):
        if not hasattr(self, 'connection'):
            await self.connect()

        try:
            self.decode_auth = Crypto.decode_auth(self.auth) if self.auth is not None else None
            self.import_key = pkcs1_15.new(RSA.import_key(self.private_key.encode())) if self.private_key else None
            await self.get_me()

        except exceptions.NotRegistered:
            if not phone_number:
                raise ValueError("📱 Phone number is required as a parameter")

            # Normalize phone number
            if phone_number.startswith('0'):
                phone_number = '98{}'.format(phone_number[1:])
            elif phone_number.startswith('+98'):
                phone_number = phone_number[1:]
            elif phone_number.startswith('0098'):
                phone_number = phone_number[2:]

            result = await self.send_code(phone_number=phone_number, pass_key=pass_key)

            if result.status == 'SendPassKey' and not pass_key:
                raise ValueError("🔑 PassKey is required for two-step verification accounts")

            public_key, self.private_key = Crypto.create_keys()

            if not phone_code:
                raise ValueError("✅ Verification code is required as a parameter")

            result = await self.sign_in(
                phone_code=phone_code,
                phone_number=phone_number,
                phone_code_hash=result.phone_code_hash,
                public_key=public_key)

            if result.status == 'OK':
                result.auth = Crypto.decrypt_RSA_OAEP(self.private_key, result.auth)
                self.key = Crypto.passphrase(result.auth)
                self.auth = result.auth
                self.decode_auth = Crypto.decode_auth(self.auth)
                self.import_key = pkcs1_15.new(RSA.import_key(self.private_key.encode())) if self.private_key else None
                self.session.insert(
                    auth=self.auth,
                    guid=result.user.user_guid,
                    user_agent=self.user_agent,
                    phone_number=result.user.phone,
                    private_key=self.private_key)

                await self.register_device()

        return self
