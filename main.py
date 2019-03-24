import sys
import os
import struct
import time
from Crypto.Cipher import AES, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64
from Crypto.Cipher import Blowfish
from Crypto import Random
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QMainWindow, QFileDialog, QLineEdit, QTabWidget

class InvalidFile(Exception):
    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = 'EndeCryptor'
        self.width = 600
        self.height = 375
        self.file = ''
        self.lbl = None
        self.txtEdit = None
        self.tabWidget = None
        self.initGUI()

    def initGUI(self):
        self.setWindowTitle(self.title)
        self.setMinimumSize(self.width, self.height)
        self.setMaximumSize(self.width, self.height)
        self.resize(self.width, self.height)
        self.move(300, 300)

        # textEdit
        txtEdit = QLineEdit('', self)
        txtEdit.move(20, 20)
        txtEdit.setFixedWidth(450)
        self.txtEdit = txtEdit

        # btnEncrypt
        btnEncrypt = QPushButton('Encrypt', self)
        btnEncrypt.move(365, 325)
        btnEncrypt.setToolTip('Encryt the selected file')
        btnEncrypt.clicked.connect(self.Encrypt)

        # btnDecrypt
        btnDecrypt = QPushButton('Decrypt', self)
        btnDecrypt.move(475, 325)
        btnDecrypt.setToolTip('Decryt the selected file')
        btnDecrypt.clicked.connect(self.Decrypt)

        # lbl
        lbl = QLabel('No file seleted!', self)
        lbl.move(20, 70)
        lbl.resize(600, 20)
        self.lbl = lbl
        
        # open file button
        btnOpenFile = QPushButton('Open', self)
        btnOpenFile.move(475, 20)
        btnOpenFile.setToolTip('Click to open a file')
        btnOpenFile.clicked.connect(self.openFile)

        # Tab Widget
        self.tabWidget = TabWidget(self)
        self.tabWidget.move(10, 90)
        self.tabWidget.resize(575, 200)

        
        self.show()

    def lblText(self, text, colorText):
        self.lbl.setText(text)
        self.lbl.setStyleSheet('color: ' + colorText)

    def openFile(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"Choose a file", "","All Files (*);;Python Files(*.py)", options=options)
        self.file = fileName
        self.txtEdit.setText(self.file)
        if self.lbl.text() == 'Please choos a file first!':
            self.lbl.setText('Proceed')
            self.lbl.setStyleSheet('color: black')
        else:
            self.lbl.setText('File chosen!')
            self.lbl.setStyleSheet('color: black')

    def Encrypt(self):
        self.file = self.txtEdit.text()
        try:
            start = time.time()
            if self.tabWidget.currentIndex() == 0:
                self.EncryptFileAES()
            if self.tabWidget.currentIndex() == 1:
                self.EncryptFileRSA()
            if self.tabWidget.currentIndex() == 2:
                self.EncryptFileBlowFish()
            end = time.time()
            self.lblText('File has been encrypted successfully in ' + str(end -start) + ' seconds!', 'green')            
        except InvalidFile:
            self.lblText('Invalid file path!', 'red')
            return
        except Exception as e:
            self.lblText('Encryption failed', 'red')

    def Decrypt(self):
        self.file = self.txtEdit.text()
        try:
            start = time.time()
            if self.tabWidget.currentIndex() == 0:
                self.DecryptFileAES()
            if self.tabWidget.currentIndex() == 1:
                self.DecryptFileRSA()
            if self.tabWidget.currentIndex() == 2:
                self.DecryptFileBlowFish()
            end = time.time()
            self.lblText('File has been decrypted successfully in ' + str(end -start) + ' seconds!', 'green')              
        except InvalidFile:
            self.lblText('Invalid file path!', 'red')
            return
        except Exception:
            self.lblText('Decryption failed', 'red')

    def EncryptFileBlowFish(self):
        # create a new blowfish cipher with an unpredictable key between 4 and 56 bytes long.
        bfkey =b''
        bfkey = self.tabWidget.getSymetricKey2()
        cipher = Blowfish.new(bfkey)

        #now we can use it to encrypt plaintext

        fileName = self.file
        if not os.path.isfile(fileName):
            raise InvalidFile()
        print("Encrypt BlowFish " + fileName)

        data = b''
        with open(fileName, 'rb') as fin:
            data = fin.read()
            fin.close()

        # Input strings must be a multiple of 8 in length due to blockalgo.py 
        if len(data) % 8 != 0:
            toAdd = 8 - len(data) % 8
        for i in range(toAdd):
            data += b" "
        
        encrypted_data = cipher.encrypt(data)

        #for debug purpose
        # print(encrypted_data)
        
        #export encrypted file :
        dirname = os.path.dirname(self.file) + '/'
        onlyFileName = fileName[len(dirname):]
        with open(dirname + '[Encrypted]' + onlyFileName, 'wb') as fout:
            fsz = os.path.getsize(fileName)
            fout.write(struct.pack('<Q', fsz))
            fout.write(encrypted_data)
            fout.close()
    
    def DecryptFileBlowFish(self):
        bfkey =b''
        bfkey = self.tabWidget.getSymetricKey2()
        cipher = Blowfish.new(bfkey)

        fileName = self.file
        if not os.path.isfile(fileName):
            raise InvalidFile()
        print("Decrypt BlowFish " + fileName)

        data = b''
        with open(fileName, 'rb') as fin:
            # Read file size
            fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
            # print(fsz)
            data = fin.read()
            # print(data)
            fin.close()

        decryptedData = cipher.decrypt(data)
        decryptedData = decryptedData[:fsz]

        dirname = os.path.dirname(self.file) + '/'
        onlyFileName = fileName[len(dirname):]
        with open(dirname + '[Decrypted]' + onlyFileName, 'wb') as fout:
            fout.write(decryptedData)
            fout.close()


    def EncryptFileRSA(self):
        fileName = self.file
        if not os.path.isfile(fileName):
            raise InvalidFile()
        print("Encrypt RSA " + fileName)

        data = b''
        with open(fileName, 'rb') as fin:
            data = fin.read()
            fin.close()
        if self.tabWidget.getKeyFile() == "":
            self.lblText('Please choose a key file!', 'red')
            return
        else:
            with open(self.tabWidget.getKeyFile(), 'rb') as fkey:
                keyData = fkey.read()
                fkey.close()

                # Import key and use for encryption using PKCS1_OAEP
                RSAKey = RSA.importKey(keyData)
                RSAKey = PKCS1_OAEP.new(RSAKey)

                # Compress file data
                data = zlib.compress(data)

                chunk_size = 470 # 512 - 42
                offset = 0
                end_loop = False
                encryptedData = b''

                while not end_loop:
                    #The chunk
                    chunk = data[offset:offset + chunk_size]

                    if len(chunk) % chunk_size != 0:
                        end_loop = True
                        chunk += b" " * (chunk_size - len(chunk))

                    #Append the encrypted chunk to the overall encrypted file
                    encryptedData += RSAKey.encrypt(chunk)
                    
                    #Increase the offset by chunk size
                    offset += chunk_size

                #Base 64 encode the encrypted file
                b64EncryptedData = base64.b64encode(encryptedData)

                dirname = os.path.dirname(self.file) + '/'
                onlyFileName = fileName[len(dirname):]
                with open(dirname + '[Encrypted]' + onlyFileName, 'wb') as fout:
                    fout.write(b64EncryptedData)
                    fout.close()

    def DecryptFileRSA(self):
        fileName = self.file
        if not os.path.isfile(fileName):
            raise InvalidFile()
        print("Decrypt RSA " + fileName)

        data = b''
        with open(fileName, 'rb') as fin:
            data = fin.read()
            fin.close()
        if self.tabWidget.getKeyFile() == "":
            self.lblText('Please choose a key file!', 'red')
            return
        else:
            with open(self.tabWidget.getKeyFile(), 'rb') as fkey:
                keyData = fkey.read()
                fkey.close()

                # Import key and use for encryption using PKCS1_OAEP
                RSAKey = RSA.importKey(keyData)
                RSAKey = PKCS1_OAEP.new(RSAKey)

                #Base 64 decode the data
                data = base64.b64decode(data)

                chunk_size = 512
                offset = 0
                zipDecryptedData = b''

                #keep loop going as long as we have chunks to decrypt
                while offset < len(data):
                    #The chunk
                    chunk = data[offset: offset + chunk_size]

                    #Append the decrypted chunk to the overall decrypted file
                    zipDecryptedData += RSAKey.decrypt(chunk)

                    #Increase the offset by chunk size
                    offset += chunk_size

                #return the decompressed decrypted data
                decryptedData =  zlib.decompress(zipDecryptedData)

                dirname = os.path.dirname(self.file) + '/'
                onlyFileName = fileName[len(dirname):]
                with open(dirname + '[Decrypted]' + onlyFileName, 'wb') as fout:
                    fout.write(decryptedData)
                    fout.close()

    def EncryptFileAES(self):
        fileName = self.file
        if not os.path.isfile(fileName):
            raise InvalidFile()
        if self.file:
            fileName = self.file
            print("Encrypt AES " + fileName)
            # Create encryptor
            iv = Random.new().read(16)
            # print(sys.getsizeof(iv))
            encryptor = AES.new(self.tabWidget.getSymetricKey(), AES.MODE_CBC, iv)
            
            # Write the file size
            fsz = os.path.getsize(fileName)


            dirname = os.path.dirname(fileName) + '/'
            onlyFileName = fileName[len(dirname):]
            with open(dirname + "[Encrypted]" + onlyFileName, 'wb') as fout:
                fout.write(struct.pack('<Q', fsz))
                fout.write(iv)

                # Adjust the last block
                sz = 2048
                with open(fileName, 'rb') as fin:
                    while True:
                        data = fin.read(sz)
                        n = len(data)
                        if n == 0:
                            break # Stop if file is over
                        elif n % 16 != 0:
                            data += b' ' * (16 - n % 16) # fill in last block with spaces
                        encryptedData = encryptor.encrypt(data)
                        fout.write(encryptedData)
        else:
            self.lblText('Please choose a file first!', 'red')
 
    def DecryptFileAES(self):
        fileName = self.file
        if not os.path.isfile(fileName):
            raise InvalidFile()
        if self.file:
            fileName = self.file
            print("Decrypt " + fileName)
            with open(fileName, 'rb') as fin:
                # Read meta data
                fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
                iv = fin.read(16)
                decryptor = AES.new(self.tabWidget.getSymetricKey(), AES.MODE_CBC, iv)

                # Decrypt data
                dirname = os.path.dirname(fileName) + '/'
                onlyFileName = fileName[len(dirname):]
                with open(dirname + "[Decrypted]" + onlyFileName, 'wb') as fout:
                    sz = 2048
                    while True:
                        data = fin.read(sz)
                        n = len(data)
                        if n == 0:
                            break
                        decd = decryptor.decrypt(data)
                        n = len(decd)
                        if fsz > n:
                            fout.write(decd)
                        else:
                            fout.write(decd[:fsz]) # remove last spaces
                        fsz -= n
        else:
            self.lblText('Please choose a file first!', 'red')

class TabWidget(QWidget):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        self.app = parent
        # Tabs
        self.tabs = QTabWidget()
        self.tabSymetricKey = QWidget()
        self.tabSymetricKey2 = QWidget()
        self.tabPublicKey = QWidget()

        # Tab AES
        lbl = QLabel('Symetric key: ', self.tabSymetricKey)
        lbl.move(10, 25)
        self.aesKeyInput = QLineEdit('Type in symetric key', self.tabSymetricKey)
        self.aesKeyInput.setFixedWidth(200)
        self.aesKeyInput.move(100, 20) # symetric key input
        self.aesKeyInput.textChanged.connect(self.checkInputAES)

        # Tab RSA
        btnGenKeys = QPushButton('Generate Keys', self.tabPublicKey)
        btnGenKeys.move(10, 25)
        btnGenKeys.clicked.connect(self.generateKeys)
        lblWarn = QLabel('<span style=\"color: #CC0000 \">Notice:</span> Use public key to encrypt and private key to decrypt', self.tabPublicKey)
        lblWarn.move(125, 30)            
        lbl2 = QLabel('Choose key file:', self.tabPublicKey)
        lbl2.move(10, 65)
        txtOpenKeyFile = QLineEdit('', self.tabPublicKey)
        txtOpenKeyFile.setFixedWidth(300)
        txtOpenKeyFile.move(120, 60)
        btnOpenKeyFile = QPushButton('Open', self.tabPublicKey)
        btnOpenKeyFile.move(425, 60)
        btnOpenKeyFile.clicked.connect(self.openKeyFile)
        self.keyFile = None
        self.openKeyFile = txtOpenKeyFile


        #Tab BlowFish 
        lbl = QLabel('Symetric key: ', self.tabSymetricKey2)
        lbl.move(10, 25)
        self.bfKeyInput = QLineEdit('Type in symetric key', self.tabSymetricKey2)
        self.bfKeyInput.setFixedWidth(200)
        self.bfKeyInput.move(100, 20) # symetric key input
        self.bfKeyInput.textChanged.connect(self.checkInputBlowFish)


        # Showing tabs
        self.tabs.addTab(self.tabSymetricKey, 'AES')
        self.tabs.addTab(self.tabPublicKey, 'RSA')
        self.tabs.addTab(self.tabSymetricKey2, 'BlowFish')
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

    def getKeyFile(self):
        return self.keyFile

    def generateKeys(self):
        # Generate public and private keys pair
        keyPair = RSA.generate(4096, e=65537)

        # Private key to PEM format
        privateKey = keyPair.exportKey("PEM")

        # Public key to PEM format
        publicKey = keyPair.publickey().exportKey("PEM")

        # Create keys files
        with open('private.pem', 'wb') as fprivate:
            fprivate.write(privateKey)
            fprivate.close()
        with open('public.pem', 'wb') as fpublic:
            fpublic.write(publicKey)
            fpublic.close()
        self.app.lblText('Keys has been created!', 'blue')

    def openKeyFile(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"Choose key file", "","PEM(*.pem)", options=options)
        self.keyFile = fileName
        self.openKeyFile.setText(self.keyFile)


    def checkInputAES(self):
        if len(self.aesKeyInput.text()) is not 16:
            self.app.lblText('The AES symetric key will be cast to 16 bytes long!', '#AAAA00')
        else:
            self.app.lblText('The AES symetric key is OK!', '#00AA00')

    def checkInputBlowFish(self):
        if len(self.bfKeyInput.text()) < 4 or len(self.bfKeyInput.text()) > 56:
            self.app.lblText('The BlowFish symetric key is between 4 and 56 bytes long', '#AAAA00')
        else:
            self.app.lblText('The BlowFish symetric key is OK!', '#00AA00')

    def currentIndex(self):
        return self.tabs.currentIndex()

    def getSymetricKey(self):
        if self.aesKeyInput.text() == "":
            return " " * 16
        elif len(self.aesKeyInput.text()) < 16:
            # key is not 16 bytes long, make it 16 bytes long
            betterKeyInput = self.aesKeyInput.text() + " " * (16 - len(self.aesKeyInput.text()))
            return betterKeyInput
        elif len(self.aesKeyInput.text()) > 16:
            # key is not 16 bytes long, make it 16 bytes long
            betterKeyInput = self.aesKeyInput.text()[0:16]
            return betterKeyInput
        else:
            return self.aesKeyInput.text()

    # get Symetric for blowFish
    def getSymetricKey2(self):
        if self.bfKeyInput.text() == "":
            return " " * 4
        elif len(self.bfKeyInput.text()) < 4:
            # key is not 4 bytes long, make it 4 bytes long
            betterKeyInput = self.bfKeyInput.text() + " " * (4 - len(self.aesKeyInput.text()))
            return betterKeyInput
        elif len(self.bfKeyInput.text()) > 56:
            # key is not 16 bytes long, make it 16 bytes long
            betterKeyInput = self.aesKeyInput.text()[0:56]
            return betterKeyInput
        else:
            return self.bfKeyInput.text()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())