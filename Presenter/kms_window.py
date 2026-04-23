import os
import secrets

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QComboBox

from Business.crypto_service import OpenSSLService
from Model.models import app, db, Key
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.file_repo import FileRepository
from Repositories.framework_repo import FrameworkRepository
from Repositories.performance_repo import PerformanceRepository


class KMSWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.selected_file_path = None
        self.init_ui()
        self.load_data()

    def init_ui(self):
        self.setWindowTitle('KMS - Local Key Management')
        self.setFixedSize(450, 300)

        layout = QVBoxLayout()

        self.file_label = QLabel("No file selected")
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.file_label)

        self.btn_select_file = QPushButton("Select File")
        self.btn_select_file.clicked.connect(self.select_file)
        layout.addWidget(self.btn_select_file)

        layout.addWidget(QLabel("Select Algorithm:"))
        self.combo_alg = QComboBox()
        layout.addWidget(self.combo_alg)

        layout.addWidget(QLabel("Select Framework:"))
        self.combo_fw = QComboBox()
        layout.addWidget(self.combo_fw)

        self.btn_encrypt = QPushButton("Encrypt File")
        self.btn_encrypt.setStyleSheet("background-color: #007bff; color: white; padding: 10px;")
        self.btn_encrypt.clicked.connect(self.encrypt_file)
        layout.addWidget(self.btn_encrypt)

        self.setLayout(layout)

    def load_data(self):
        with app.app_context():
            algorithms = AlgorithmRepository.get_all()
            for alg in algorithms:
                self.combo_alg.addItem(f"{alg.name} ({alg.type})", alg.id)

            frameworks = FrameworkRepository.get_all()
            for fw in frameworks:
                self.combo_fw.addItem(f"{fw.name} {fw.version}", fw.id)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", "All Files (*)")
        if file_path:
            self.selected_file_path = file_path
            file_name = os.path.basename(file_path)
            self.file_label.setText(f"Selected: {file_name}")

    def encrypt_file(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first!")
            return

        alg_id = self.combo_alg.currentData()
        fw_id = self.combo_fw.currentData()
        file_name = os.path.basename(self.selected_file_path)

        output_dir = os.path.join(os.getcwd(), "encrypted")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{file_name}.enc")

        with app.app_context():
            db_file = FileRepository.create(original_name=file_name)

            raw_key = secrets.token_bytes(32)
            new_key = Key(algorithm_id=alg_id, key_value=raw_key)
            db.session.add(new_key)
            db.session.commit()

            exec_time_ms = OpenSSLService.encrypt_aes_256_cbc(
                input_path=self.selected_file_path,
                output_path=output_path,
                key_bytes=raw_key
            )

            if exec_time_ms == -1:
                QMessageBox.critical(self, "Error", "OpenSSL execution failed.")
                return

            FileRepository.update_state(db_file.id, new_state="Encrypted", enc_path=output_path)

            PerformanceRepository.create(
                file_id=db_file.id,
                algorithm_id=alg_id,
                framework_id=fw_id,
                operation="Encryption",
                time_ms=exec_time_ms,
                mem_kb=0.0
            )

            QMessageBox.information(self, "Success",
                                    f"File encrypted in {exec_time_ms:.2f} ms!\nSaved to: {output_path}")
            self.selected_file_path = None
            self.file_label.setText("No file selected")
