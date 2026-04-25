import sys
from PyQt6.QtWidgets import (QApplication)
from Model.models import init_db
from Presenter.kms_window import KMSWindow


if __name__ == '__main__':
    init_db(seed=True)
    qt_app = QApplication(sys.argv)
    window = KMSWindow()
    window.show()
    sys.exit(qt_app.exec())