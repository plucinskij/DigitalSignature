from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import base64

filename = ''


def getHash():
    file = open(filename, 'rb')
    content = file.read()
    hash = SHA256.new(content)
    file.close()
    return hash


def genKeys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


def sign():
    print('Signing...')
    hash = getHash()

    private_key, public_key = genKeys()
    signature = pkcs1_15.new(private_key).sign(hash)

    with open("signature.txt", 'wb') as f:
        f.write(base64.b64encode(signature))
    f.close()
    with open("public_key.pem", 'wb') as f:
        f.write(public_key.export_key('PEM'))
    f.close()

    print('File signed')

    return signature, public_key


def check():
    hash = getHash()

    signature_file = open('signature.txt', 'r')
    signature = base64.b64decode(signature_file.read())
    signature_file.close()

    public_key_file = open('public_key.pem', 'r')
    public_key = RSA.import_key(public_key_file.read())
    public_key_file.close()
    try:
        pkcs1_15.new(public_key).verify(hash, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


if __name__ == '__main__':

    print('Enter file name. Remember that the file must be in the same folder as this program.')
    filename = input()

    print('Press 1 if you want to sign the file or 2 if you want to validate the signature')
    print(
        'If you want to validate the signature, remember that the files "public_key.pem" and "signature.txt" must be in the same folder as this program.')
    func = int(input())
    match func:
        case 1:
            sign()
        case 2:
            check()
        case default:
            print('Wrong number')
