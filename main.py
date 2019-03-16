import sys
import os
import struct
from Crypto.Cipher import AES
from Crypto import Random
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QMainWindow, QFileDialog, QLineEdit

def Encrypt():
    print('Encrypt')

def Decrypt():
    print('Decrypt')

class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = 'EndeCryptor'
        self.width = 600
        self.height = 375
        self.file = None
        self.lbl = None
        self.txtEdit = None
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
        btnEncrypt.clicked.connect(self.openEncryptFile)

        # btnDecrypt
        btnDecrypt = QPushButton('Decrypt', self)
        btnDecrypt.move(475, 325)
        btnDecrypt.setToolTip('Decryt the selected file')
        btnDecrypt.clicked.connect(self.openDecryptFile)

        # lbl
        lbl = QLabel('No file seleted!', self)
        lbl.move(20, 70)
        lbl.resize(400, 20)
        self.lbl = lbl
        

        # open file button
        btnOpenFile = QPushButton('Open', self)
        btnOpenFile.move(475, 20)
        btnOpenFile.setToolTip('Click to open a file')
        btnOpenFile.clicked.connect(self.openFile)
        
        self.show()

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

    def openEncryptFile(self):
        if self.file:
            fileName = self.file
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
            self.lbl.setText('File has been encrypted successfully!')
            self.lbl.setStyleSheet('color: green')

        else:
            self.lbl.setText('Please choose a file first!')
            self.lbl.setStyleSheet('color: red')
 
    def openDecryptFile(self):
        if self.file:
            fileName = self.file
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
            self.lbl.setText('File has been decrypted successfully!')
            self.lbl.setStyleSheet('color: green')

        else:
            self.lbl.setText('Please choose a file first!')
            self.lbl.setStyleSheet('color: red')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())