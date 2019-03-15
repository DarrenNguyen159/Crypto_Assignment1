import sys
import os
import struct
from Crypto.Cipher import AES
from Crypto import Random
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QMainWindow, QFileDialog

def Encrypt():
    print('Encrypt')

def Decrypt():
    print('Decrypt')

class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = 'EndeCryptor'
        self.width = 400
        self.height = 250
        self.initGUI()
    
    def initGUI(self):
        self.setWindowTitle(self.title)
        self.setMinimumSize(self.width, self.height)
        self.setMaximumSize(self.width, self.height)
        self.resize(self.width, self.height)
        self.move(300, 300)

        # btnEncrypt
        btnEncrypt = QPushButton('Encrypt', self)
        btnEncrypt.move(80, 100)
        btnEncrypt.setToolTip('Encryt the selected file')
        btnEncrypt.clicked.connect(self.openEncryptFile)

        # btnDecrypt
        btnDecrypt = QPushButton('Decrypt', self)
        btnDecrypt.move(220, 100)
        btnDecrypt.setToolTip('Decryt the selected file')
        btnDecrypt.clicked.connect(self.openDecryptFile)

        #lbl
        lbl = QLabel('Choose your file to Encrypt or Decrypt', self)
        lbl.resize(400, 20)
        self.show()

    def openEncryptFile(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"Encrypt", "","All Files (*);;Python Files(*.py)", options=options)
        if fileName:
            print("Encrypt " + fileName)
            # Create encryptor
            iv = Random.new().read(16)
            # print(sys.getsizeof(iv))
            encryptor = AES.new('This is a key123', AES.MODE_CBC, iv)
            
            # Write the file size
            fsz = os.path.getsize(fileName)

            with open(fileName+"[Encrypted]", 'wb') as fout:
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
 
    def openDecryptFile(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"Decrypt", "","All Files (*);;Python Files(*.py)", options=options)
        if fileName:
            print("Decrypt " + fileName)
            with open(fileName, 'rb') as fin:
                # Read meta data
                fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
                iv = fin.read(16)
                decryptor = AES.new('This is a key123', AES.MODE_CBC, iv)

                # Decrypt data
                with open(fileName+"[Decrypted]", 'wb') as fout:
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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())