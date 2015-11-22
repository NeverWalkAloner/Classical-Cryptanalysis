import string
import random
ALPHABET = string.ascii_uppercase

def readfile(file):
    f=open(file, mode='r')
    message=''
    for ch in f.read():
        if 65 <= ord(ch) <= 90 or 97 <= ord(ch) <= 122:
            message+=ch.upper()
    f.close()
    return message

#Build shifted alphabet
def offset(char, offset):
    return ALPHABET[(ALPHABET.index(char)+offset)%26]

class Caesar:
    @staticmethod
    def encrypt(message, key):
        return ''.join(map(offset, list(message), [key,]*len(message)))

    @staticmethod
    def decrypt(ciphertext, key):
        return ''.join(map(offset, list(ciphertext), [26-key,]*len(ciphertext)))

class Vigenere:
    @staticmethod
    def encrypt(message, key):
        return ''.join(map(offset, message, list(map(lambda x: ALPHABET.index(x), key))*(len(message)//len(key)+1)))

    @staticmethod
    def decrypt(ciphertext, key):
        return ''.join(map(offset, ciphertext, list(map(lambda x: 26-ALPHABET.index(x), key))*(len(ciphertext)//len(key)+1)))

class Substitution:
    @staticmethod
    def encrypt(message, key):
        cipher_alph = Substitution.buildAlphabet(key)
        return ''.join(cipher_alph[ALPHABET.index(ch.upper())] for ch in message)

    #Built substitution alphabet by key
    @staticmethod
    def buildAlphabet(key):
        offseted_alph = ''.join(map(offset, list(ALPHABET), [ALPHABET.index(key.upper()[-1])+1,]*len(ALPHABET)))
        return (key.upper()+''.join([ch for ch in offseted_alph if not (ch in key.upper())]))

    @staticmethod
    def decrypt(ciphertex, key):
        cipher_alph = Substitution.buildAlphabet(key)
        return ''.join(ALPHABET[cipher_alph.index(ch.upper())] for ch in ciphertex)

class Affine:
    @staticmethod
    def modReverse(a, b):
        r, s, t = [min(a, b), max(a, b)], [1, 0], [0,1]
        while r[-1]!=1:
            q = r[-2]//r[-1]
            r.append(r[-2]-q*r[-1])
            s.append(s[-2]-q*s[-1])
            t.append(t[-2]-q*t[-1])
        return (s[-1]%r[1])

    #key should be the tuple
    @staticmethod
    def encrypt(message, key):
        return ''.join(ALPHABET[(ALPHABET.index(ch)*key[0]+key[1])%26] for ch in message)

    #key should be the tuple
    @staticmethod
    def decrypt(ciphertext, key):
        try:
            return ''.join(ALPHABET[Affine.modReverse(key[0], 26)*(ALPHABET.index(ch)-key[1])%26] for ch in ciphertext)
        except ZeroDivisionError:
            pass

class ColumnarTransposition:
    @staticmethod
    def encrypt(message, key):
        message=message+'X'*((0-len(message)%len(key))%len(key))
        res = ''.join([message[k] for i in ColumnarTransposition.transformkey(key) for k in range(len(message)) if k%len(key) == i])
        return res

    @staticmethod
    def decrypt(ciphertext, key):
        return  ''.join([ciphertext[ColumnarTransposition.transformkey(key).index(i)*len(ciphertext)//len(key)+k] for k in range(len(ciphertext)//len(key)) for i in range(len(key))])

    @staticmethod
    def transformkey(key):
        return [i[0] for i in sorted([i for i in enumerate(key)], key=lambda x: x[1])]

class Playfair:
    @staticmethod
    def buildtable(key):
        return ''.join(sorted(set(key), key=lambda x: key.index(x)))+''.join([ch for ch in ALPHABET if not (ch in key) and ch!='J'])

    #Padding message with X if two letters found in message in a row or length of message is odd
    @staticmethod
    def padding(message):
        list_message=list(message)
        i = 1
        while i < len(list_message):
            if list_message[i]==list_message[i-1]:
                list_message.insert(i, 'X')
            i += 2
        if len(list_message)%2!=0:
            list_message.append('X')
        return [''.join(list_message[a:a+2]) for a in range(0, len(list_message), 2)]

    @staticmethod
    def substitution(message, table, *, mode):
        #table=Playfair.buildtable(key)
        if mode == 1:
            message=message.replace('J', 'I')
        list_message=Playfair.padding(message)
        list_pos=[[[table.index(elem[0])//5, table.index(elem[0])%5], [table.index(elem[1])//5, table.index(elem[1])%5]] for elem in list_message]
        list_pos2=[]
        for elem in list_pos:
            if elem[0][0]==elem[1][0]:
                list_pos2.append([[elem[0][0], (elem[0][1]+mode)%5], [elem[1][0], (elem[1][1]+mode)%5]])
            elif elem[0][1]==elem[1][1]:
                list_pos2.append([[(elem[0][0]+mode)%5, elem[0][1]], [(elem[1][0]+mode)%5, elem[1][1]]])
            else:
                list_pos2.append([[elem[0][0], elem[1][1]], [elem[1][0], elem[0][1]]])
        c=''.join([table[e[0][0]*5+e[0][1]]+table[e[1][0]*5+e[1][1]] for e in list_pos2])
        return c

    @staticmethod
    def encrypt(message, key):
        return Playfair.substitution(message, key, mode=1)

    @staticmethod
    def decrypt(message, key):
        return Playfair.substitution(message, key, mode=-1)

class PolybiusSquare:
    @staticmethod
    def encrypt(message, key, letters):
        return ''.join([letters[key.index(ch)//5]+letters[key.index(ch)%5] for ch in message])

    @staticmethod
    def decrypt(ciphertext, key, letters):
        c_list = [ciphertext[i-1]+ciphertext[i] for i in range(1, len(ciphertext), 2)]
        return ''.join([key[letters.index(ch[0])*5+letters.index(ch[1])] for ch in c_list])

    @staticmethod
    def generatekey():
        alph = ALPHABET.replace('J', '')
        l = list(alph)
        random.shuffle(l)
        return ''.join(l)

class Adfgx:
    @staticmethod
    def encrypt(message, key1, key2):
        stage1 = PolybiusSquare.encrypt(message, key1, 'ADFGX')
        stage2 = ColumnarTransposition.encrypt(stage1, key2)
        return stage2

    @staticmethod
    def decrypt(ciphertext, key1, key2):
        stage1 = ColumnarTransposition.decrypt(ciphertext, key2)
        stage2 = PolybiusSquare.decrypt(stage1, key1, 'ADFGX')
        return stage2


if __name__=='__main__':
    #Caesar test
    print('---Caesar---')
    test = 'DEFENDTHEEASTWALLOFTHECASTLE'
    k = 1
    c = Caesar.encrypt(test, k)
    d = Caesar.decrypt(c, k)
    print(c)
    print(d)

    #Vigenere test
    print('---Vigenere---')
    test = 'DEFENDTHEEASTWALLOFTHECASTLE'
    c = Vigenere.encrypt(test, 'FORTIFICATION'.upper())
    d = Vigenere.decrypt(c, 'FORTIFICATION'.upper())
    print(c)
    print(d)

    #Substitution test
    print('---Substitution---')
    test='DEFENDTHEEASTWALLOFTHECASTLE'
    c = Substitution.encrypt(test, 'zebra')
    print(c)
    d = Substitution.decrypt(c, 'zebra')
    print(d)

    #Affine test
    print('---Affine---')
    test = 'DEFENDTHEEASTWALLOFTHECASTLE'
    c = Affine.encrypt(test, (5, 7))
    print(c)
    d = Affine.decrypt(c, (5, 7))
    print(d)

    #Atbash test
    print('---Atbash---')
    test = ALPHABET
    c = Affine.encrypt(test, (25, 25))
    print(c)
    d = Affine.decrypt(c, (25, 25))
    print(d)

    #Columnar Transposition test
    print('---Columnar Transposition---')
    test = 'DEFENDTHEEASTWALLOFTHECASTLE'.upper()
    c = ColumnarTransposition.encrypt(test, 'GERMAN')
    print(c)
    d = ColumnarTransposition.decrypt(c, 'GERMAN')
    print(d)

    #Playfair test
    print('---Playfair Cipher---')
    c = Playfair.encrypt('wearediscoveredsaveyourselfx'.upper(), 'monarchy'.upper())
    print(c)
    d = Playfair.decrypt(c, 'monarchy'.upper())
    print(d)

    #Polybius square test
    print('---Polybius Square Cipher---')
    key = PolybiusSquare.generatekey()
    test = 'DEFENDTHEEASTWALLOFTHECASTLE'
    c = PolybiusSquare.encrypt(test.upper(), list(key), 'ABCDE')
    print(c)
    d = PolybiusSquare.decrypt(c, list(key), 'ABCDE')
    print(d)

    #ADFGX test
    print('---ADFGX Cipher---')
    key1 = 'phqgmeaynofdxkrcvszwbutil'.upper()
    key2 = 'GERMAN'
    test = 'ATTACK'
    c = Adfgx.encrypt(test, key1, key2)
    print(c)
    d = Adfgx.decrypt(c, key1, key2)
    print(d)
