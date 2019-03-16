import sys
import os
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QMainWindow, QFileDialog, QLineEdit, QTabWidget

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

    def openEncryptFile(self):
        if self.file:
            fileName = self.file
            print("Encrypt " + fileName)
            # Create encryptor
            iv = Random.new().read(16)
            # print(sys.getsizeof(iv))
            encryptor = AES.new(self.tabWidget.getSymetricKey(), AES.MODE_CBC, iv)
            
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
            self.lblText('File has been encrypted successfully!', 'green')

        else:
            self.lblText('Please choose a file first!', 'red')
 
    def openDecryptFile(self):
        if self.file:
            fileName = self.file
            print("Decrypt " + fileName)
            with open(fileName, 'rb') as fin:
                # Read meta data
                fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
                iv = fin.read(16)
                decryptor = AES.new(self.tabWidget.getSymetricKey(), AES.MODE_CBC, iv)

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
            self.lblText('File has been decrypted successfully!', 'green')

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
        self.tabPublicKey = QWidget()

        # Tab AES
        lbl = QLabel('Symetric key: ', self.tabSymetricKey)
        lbl.move(10, 25)
        self.aesKeyInput = QLineEdit('Type in symetric key', self.tabSymetricKey)
        self.aesKeyInput.setFixedWidth(200)
        self.aesKeyInput.move(100, 20) # symetric key input
        self.aesKeyInput.textChanged.connect(self.checkInputAES)

        # Showing tabs
        self.tabs.addTab(self.tabSymetricKey, 'AES')
        self.tabs.addTab(self.tabPublicKey, 'RSA')
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

    def checkInputAES(self):
        if len(self.aesKeyInput.text()) is not 16:
            self.app.lblText('The AES symetric key will be cast to 16 bytes long!', '#AAAA00')
        else:
            self.app.lblText('The AES symetric key is OK!', '#00AA00')

    def currenIndex(self):
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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())