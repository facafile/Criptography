#!/usr/bin/env python3

import pickle
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

def random_bytes(n):
    return secrets.token_bytes(n)

def shared_secret_calc(private_key, client_public_key):
    peer_public_key = pickle.loads(client_public_key)
    shared_key = private_key.exchange(peer_public_key)

    return shared_key

class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_pub_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        # Aktivne konekcije s drugim klijentima
        self.conns = {}
        # Inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        self.dh_key_pair = ()

    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        self.dh_key_pair = {"public" : public_key,
                         "private" : private_key}
        return {
            "username" : self.username,
            "DH public key" : public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
)
        }

    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """
        try:
            self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))

            self.conns[cert["username"]] = {}
            self.conns[cert["username"]]["public"] = serialization.load_pem_public_key(
            cert["DH public key"],
            backend=default_backend()
            )
            shared_key = self.dh_key_pair["private"].exchange(self.conns[cert["username"]]["public"])

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=None,
            ).derive(shared_key)

            self.conns[cert["username"]]["root"] = derived_key
            self.conns[cert["username"]]["new"] = 1
            return
        except Exception as e:
            return

    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """
        if self.conns[username]["new"] == 1:
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()

            self.conns[username]["dh_key_pair"] = {"public": public_key,
                                "private": private_key}
            self.conns[username]["new"] = 0
            shared_key = self.conns[username]["dh_key_pair"]["private"].exchange(self.conns[username]["public"])
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=self.conns[username]["root"],
                info=None,
            ).derive(shared_key)
            self.conns[username]["root"] = derived_key[:32]
            self.conns[username]["send"] = derived_key[32:]

        derived_key3 = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'2024',
            info=None,
        ).derive(self.conns[username]["send"])

        self.conns[username]["send"] = derived_key3[:32]
        iv = random_bytes(16)
        cipher = AESGCM(derived_key3[32:])
        encrypted = cipher.encrypt(iv, message.encode('utf-8'), None)

        return (self.conns[username]["dh_key_pair"]["public"], iv, encrypted)



    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        if self.conns[username]["public"] != message[0]:
            self.conns[username]["public"] = message[0]
            self.conns[username]["new"] = 1
            if("dh_key_pair" in self.conns[username]):
                shared_key = self.conns[username]["dh_key_pair"]["private"].exchange(self.conns[username]["public"])
            else:
                shared_key = self.dh_key_pair["private"].exchange(self.conns[username]["public"])
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=self.conns[username]["root"],
                info=None,
            ).derive(shared_key)

            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()

            self.conns[username]["dh_key_pair"] = {"public": public_key,
                                "private": private_key}


            self.conns[username]["root"] = derived_key[:32]
            self.conns[username]["receive"] = derived_key[32:]

        derived_key3 = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'2024',
            info=None,
        ).derive(self.conns[username]["receive"])

        self.conns[username]["receive"] = derived_key3[:32]
        cipher = AESGCM(derived_key3[32:])
        decrypted = cipher.decrypt(message[1], message[2], None)

        return decrypted.decode('utf-8')


def main():
    pass

if __name__ == "__main__":
    main()
