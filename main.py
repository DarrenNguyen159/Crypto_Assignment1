import sys
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
        btnEncrypt.clicked.connect(self.openFileNameDialog)

        # btnDecrypt
        btnDecrypt = QPushButton('Decrypt', self)
        btnDecrypt.move(220, 100)
        btnDecrypt.setToolTip('Decryt the selected file')
        btnDecrypt.clicked.connect(Decrypt)

        #lbl
        lbl = QLabel('Choose your file to Encrypt or Decrypt', self)
        lbl.resize(400, 20)
        self.show()

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"QFileDialog.getOpenFileName()", "","All Files (*);;Python Files(*.py)", options=options)
        if fileName:
            print("Open" + fileName)
            # open and read the file, TODO: Replace the code below
            f = open(fileName, 'r')
            content = f.read()
            f.close()

            f = open(fileName, 'w')
            f.write("Let assume this is encrypted:" + content)
            f.close()
 
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())