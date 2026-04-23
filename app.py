import sys
from PyQt6.QtWidgets import (QApplication)
from Presenter.kms_window import KMSWindow


if __name__ == '__main__':
    qt_app = QApplication(sys.argv)
    window = KMSWindow()
    window.show()
    sys.exit(qt_app.exec())