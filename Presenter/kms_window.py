import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from Business.crypto_service import (
    CryptoManagerService,
    CryptoServiceError,
    FileManagementService,
    KeyManagementService,
)
from Model.models import app, init_db
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.file_repo import FileRepository
from Repositories.framework_repo import FrameworkRepository
from Repositories.key_repo import KeyRepository
from Repositories.operation_repo import OperationRepository
from Repositories.performance_repo import PerformanceRepository


class KMSWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.selected_file_path = None

        init_db(seed=True)

        self.init_ui()
        self.load_data()

    def init_ui(self):
        self.setWindowTitle("Local Encryption Key Management System")
        self.setMinimumSize(1300, 820)
        self.setStyleSheet(self._build_stylesheet())

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(14)

        root.addWidget(self._build_header())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([430, 870])

        root.addWidget(splitter, 1)

    def _build_header(self):
        header = QFrame()
        header.setObjectName("header")

        layout = QHBoxLayout(header)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(18)

        title_box = QVBoxLayout()
        title_box.setSpacing(6)

        title = QLabel("Local Encryption Key Management System")
        title.setObjectName("headerTitle")

        subtitle = QLabel(
            "Manage encryption keys, files, algorithms, frameworks, hashes and performance results."
        )
        subtitle.setObjectName("headerSubtitle")
        subtitle.setWordWrap(True)

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        layout.addLayout(title_box, 1)

        badges = QHBoxLayout()
        badges.setSpacing(10)

        self.framework_badge = QLabel("Frameworks: 0")
        self.framework_badge.setObjectName("badge")

        self.algorithm_badge = QLabel("Algorithms: 0")
        self.algorithm_badge.setObjectName("badge")

        badges.addWidget(self.framework_badge)
        badges.addWidget(self.algorithm_badge)

        layout.addLayout(badges)

        return header

    def _build_left_panel(self):
        panel = QFrame()
        panel.setObjectName("leftPanel")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        file_group = QGroupBox("1. File Management")
        file_layout = QVBoxLayout(file_group)
        file_layout.setContentsMargins(12, 12, 12, 12)
        file_layout.setSpacing(10)

        self.file_label = QLabel("No local file selected.")
        self.file_label.setObjectName("infoLabel")
        self.file_label.setWordWrap(True)
        self.file_label.setMinimumHeight(42)
        file_layout.addWidget(self.file_label)

        file_buttons = QHBoxLayout()
        file_buttons.setSpacing(8)

        self.btn_select_file = QPushButton("Browse File")
        self.btn_select_file.clicked.connect(self.select_file)

        self.btn_register_file = QPushButton("Register File")
        self.btn_register_file.setObjectName("secondaryButton")
        self.btn_register_file.clicked.connect(self.register_file)

        file_buttons.addWidget(self.btn_select_file)
        file_buttons.addWidget(self.btn_register_file)

        file_layout.addLayout(file_buttons)
        layout.addWidget(file_group)

        setup_group = QGroupBox("2. Crypto Setup")
        setup_group.setFixedHeight(255)

        setup_layout = QVBoxLayout(setup_group)
        setup_layout.setContentsMargins(12, 0, 12, 8)
        setup_layout.setSpacing(2)

        self.combo_files = self._combo()
        self.combo_files.currentIndexChanged.connect(self.refresh_details)

        self.combo_alg = self._combo()
        self.combo_alg.currentIndexChanged.connect(self._selection_changed)

        self.combo_fw = self._combo()
        self.combo_fw.currentIndexChanged.connect(self._selection_changed)

        self.combo_key = self._combo()

        setup_layout.addWidget(self._label("Managed File"))
        setup_layout.addWidget(self.combo_files)

        setup_layout.addWidget(self._label("Algorithm"))
        setup_layout.addWidget(self.combo_alg)

        setup_layout.addWidget(self._label("Framework"))
        setup_layout.addWidget(self.combo_fw)

        setup_layout.addWidget(self._label("Key"))
        setup_layout.addWidget(self.combo_key)

        layout.addWidget(setup_group)

        key_group = QGroupBox("3. Key Management")
        key_layout = QVBoxLayout(key_group)
        key_layout.setContentsMargins(12, 0, 12, 12)
        key_layout.setSpacing(8)

        self.btn_generate_key = QPushButton("Generate Key")
        self.btn_generate_key.clicked.connect(self.generate_key)

        self.btn_show_keys = QPushButton("Show Stored Keys")
        self.btn_show_keys.setObjectName("neutralButton")
        self.btn_show_keys.clicked.connect(self.show_keys_debug)

        key_layout.addWidget(self.btn_generate_key)
        key_layout.addWidget(self.btn_show_keys)

        layout.addWidget(key_group)

        op_group = QGroupBox("4. Operations")
        op_layout = QVBoxLayout(op_group)
        op_layout.setContentsMargins(12, 0, 12, 12)
        op_layout.setSpacing(8)

        op_buttons = QHBoxLayout()
        op_buttons.setSpacing(8)

        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_encrypt.setObjectName("primaryButton")
        self.btn_encrypt.clicked.connect(self.encrypt_file)

        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setObjectName("dangerButton")
        self.btn_decrypt.clicked.connect(self.decrypt_file)

        op_buttons.addWidget(self.btn_encrypt)
        op_buttons.addWidget(self.btn_decrypt)

        self.btn_refresh = QPushButton("Refresh Data")
        self.btn_refresh.clicked.connect(self.load_data)

        op_layout.addLayout(op_buttons)
        op_layout.addWidget(self.btn_refresh)

        layout.addWidget(op_group)

        status_group = QGroupBox("5. Status")
        status_layout = QVBoxLayout(status_group)
        status_layout.setContentsMargins(12, 0, 12, 12)

        self.status_label = QLabel("Ready.")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignTop)

        status_layout.addWidget(self.status_label)

        layout.addWidget(status_group)
        layout.addStretch(1)

        return panel

    def _build_right_panel(self):
        panel = QFrame()
        panel.setObjectName("rightPanel")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 0, 0, 0)
        layout.setSpacing(12)

        metrics_layout = QGridLayout()
        metrics_layout.setSpacing(12)

        self.metric_file_status = self._metric_card("File Status", "No file")
        self.metric_hash_status = self._metric_card("Hash Check", "Unknown")
        self.metric_operation_count = self._metric_card("Operations", "0")
        self.metric_key_count = self._metric_card("Keys", "0")

        metrics_layout.addWidget(self.metric_file_status, 0, 0)
        metrics_layout.addWidget(self.metric_hash_status, 0, 1)
        metrics_layout.addWidget(self.metric_operation_count, 0, 2)
        metrics_layout.addWidget(self.metric_key_count, 0, 3)

        layout.addLayout(metrics_layout)

        self.file_summary = QTextEdit()
        self.file_summary.setReadOnly(True)
        self.file_summary.setObjectName("textBox")
        layout.addWidget(self._section("Selected File Overview", self.file_summary), 2)

        self.operations_table = self._table(
            ["ID", "Type", "Status", "File ID", "Framework ID", "Started", "Error"]
        )
        layout.addWidget(self._section("Recent Operations", self.operations_table), 3)

        self.performance_table = self._table(
            ["Operation ID", "Time (ms)", "Memory (MB)", "Input Size", "Output Size", "Created"]
        )
        layout.addWidget(self._section("Performance History", self.performance_table), 2)

        self.details_box = QTextEdit()
        self.details_box.setReadOnly(True)
        self.details_box.setObjectName("debugBox")
        layout.addWidget(self._section("Debug / Stored Keys", self.details_box), 2)

        return panel

    def _label(self, text):
        label = QLabel(text)
        label.setObjectName("fieldLabel")
        return label

    def _combo(self):
        combo = QComboBox()
        combo.setFixedHeight(32)
        return combo

    def _section(self, title, widget):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(widget)
        return group

    def _metric_card(self, title, value):
        card = QFrame()
        card.setObjectName("metricCard")
        card.setMinimumHeight(78)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("metricTitle")

        value_label = QLabel(value)
        value_label.setObjectName("metricValue")
        value_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(value_label)

        card.value_label = value_label
        return card

    def _table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        return table

    def _build_stylesheet(self):
        return """
        QWidget {
            background-color: #07130F;
            color: #F0FDF4;
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 13px;
        }

        QFrame#header {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 #064E3B,
                stop:0.55 #022C22,
                stop:1 #041C16
            );
            border: 1px solid #10B981;
            border-radius: 14px;
        }

        QLabel#headerTitle {
            color: #ECFDF5;
            background-color: transparent;
            font-size: 26px;
            font-weight: 900;
            letter-spacing: 0.3px;
        }

        QLabel#headerSubtitle {
            color: #A7F3D0;
            background-color: transparent;
            font-size: 13px;
            font-weight: 500;
        }

        QLabel#badge {
            background-color: #03231B;
            color: #ECFDF5;
            border: 1px solid #F97316;
            border-radius: 10px;
            padding: 9px 14px;
            font-weight: 800;
        }

        QFrame#leftPanel,
        QFrame#rightPanel {
            background-color: transparent;
        }

        QGroupBox {
            background-color: #0B2A22;
            border: 1px solid #14534A;
            border-radius: 12px;
            margin-top: 18px;
            padding-top: 14px;
            font-weight: 700;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 14px;
            top: 0px;
            padding: 2px 8px;
            border-radius: 6px;
            background-color: #021B15;
            color: #34D399;
            font-size: 12px;
            font-weight: 900;
        }

        QLabel#fieldLabel {
            color: #D1FAE5;
            background-color: transparent;
            font-size: 11px;
            font-weight: 800;
            margin-top: 0px;
            margin-bottom: 0px;
        }

        QLabel#infoLabel {
            color: #D1FAE5;
            background-color: #021B15;
            border: 1px solid #0F766E;
            border-radius: 8px;
            padding: 10px;
        }

        QLabel#statusLabel {
            color: #D1FAE5;
            background-color: #021B15;
            border: 1px solid #0F766E;
            border-radius: 8px;
            padding: 10px;
            min-height: 72px;
        }

        QFrame#metricCard {
            background-color: #022C22;
            border: 1px solid #047857;
            border-radius: 12px;
        }

        QLabel#metricTitle {
            color: #A7F3D0;
            background-color: transparent;
            font-size: 11px;
            font-weight: 900;
            text-transform: uppercase;
        }

        QLabel#metricValue {
            color: #F97316;
            background-color: transparent;
            font-size: 22px;
            font-weight: 900;
        }

        QPushButton {
            background-color: #0B2A22;
            color: #ECFDF5;
            border: 1px solid #0F766E;
            border-radius: 8px;
            padding: 9px 12px;
            font-weight: 800;
            min-height: 20px;
        }

        QPushButton:hover {
            background-color: #123C31;
            border-color: #10B981;
        }

        QPushButton#primaryButton {
            background-color: #059669;
            color: #ECFDF5;
            border: 1px solid #10B981;
        }

        QPushButton#primaryButton:hover {
            background-color: #10B981;
            color: #022C22;
        }

        QPushButton#secondaryButton {
            background-color: #F97316;
            color: #111827;
            border: 1px solid #FB923C;
        }

        QPushButton#secondaryButton:hover {
            background-color: #FB923C;
        }

        QPushButton#neutralButton {
            background-color: #0F3D33;
            color: #ECFDF5;
            border: 1px solid #0F766E;
        }

        QPushButton#neutralButton:hover {
            background-color: #155E52;
            border-color: #10B981;
        }

        QPushButton#dangerButton {
            background-color: #991B1B;
            color: #FEE2E2;
            border: 1px solid #DC2626;
        }

        QPushButton#dangerButton:hover {
            background-color: #B91C1C;
        }

        QComboBox {
            background-color: #021B15;
            color: #ECFDF5;
            border: 1px solid #0F766E;
            border-radius: 7px;
            padding: 3px 10px;
            min-height: 18px;
        }

        QComboBox:hover {
            border-color: #F97316;
        }

        QComboBox::drop-down {
            border: none;
            width: 28px;
        }

        QComboBox QAbstractItemView {
            background-color: #021B15;
            color: #ECFDF5;
            border: 1px solid #0F766E;
            selection-background-color: #F97316;
            selection-color: #111827;
        }

        QTextEdit,
        QTableWidget {
            background-color: #021B15;
            color: #D1FAE5;
            border: 1px solid #0F766E;
            border-radius: 8px;
            padding: 8px;
        }

        QTextEdit#debugBox {
            font-family: Consolas, monospace;
            color: #D1FAE5;
        }

        QHeaderView::section {
            background-color: #064E3B;
            color: #ECFDF5;
            border: none;
            border-bottom: 1px solid #0F766E;
            padding: 9px;
            font-weight: 900;
        }

        QTableWidget {
            gridline-color: transparent;
            selection-background-color: #F97316;
            selection-color: #111827;
        }

        QTableWidget::item {
            padding: 6px;
        }

        QScrollBar:vertical {
            background-color: #07130F;
            width: 10px;
        }

        QScrollBar::handle:vertical {
            background-color: #F97316;
            border-radius: 5px;
        }

        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            height: 0px;
        }

        QScrollBar:horizontal {
            background-color: #07130F;
            height: 10px;
        }

        QScrollBar::handle:horizontal {
            background-color: #F97316;
            border-radius: 5px;
        }

        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        """

    def _selection_changed(self):
        self.load_keys()
        self.refresh_details()

    def load_data(self):
        self.combo_files.blockSignals(True)
        self.combo_alg.blockSignals(True)
        self.combo_fw.blockSignals(True)
        self.combo_key.blockSignals(True)

        self.combo_files.clear()
        self.combo_alg.clear()
        self.combo_fw.clear()
        self.combo_key.clear()

        with app.app_context():
            files = FileRepository.get_all()
            algorithms = AlgorithmRepository.get_all()
            frameworks = FrameworkRepository.get_all()
            keys = KeyRepository.get_all()
            operations = OperationRepository.get_all()

            for managed_file in files:
                label = f"{managed_file.original_name} [{managed_file.status.upper()}]"
                self.combo_files.addItem(label, managed_file.id)

            for alg in algorithms:
                mode = f" / {alg.mode}" if getattr(alg, "mode", None) else ""
                self.combo_alg.addItem(f"{alg.name} ({alg.type}{mode})", alg.id)

            for fw in frameworks:
                version = f" {fw.version}" if getattr(fw, "version", None) else ""
                self.combo_fw.addItem(f"{fw.name}{version}", fw.id)

            self.framework_badge.setText(f"Frameworks: {len(frameworks)}")
            self.algorithm_badge.setText(f"Algorithms: {len(algorithms)}")
            self.metric_operation_count.value_label.setText(str(len(operations)))
            self.metric_key_count.value_label.setText(str(len(keys)))

        self.combo_files.blockSignals(False)
        self.combo_alg.blockSignals(False)
        self.combo_fw.blockSignals(False)
        self.combo_key.blockSignals(False)

        self.load_keys()
        self.refresh_details()

    def load_keys(self):
        self.combo_key.clear()

        algorithm_id = self.combo_alg.currentData()
        framework_id = self.combo_fw.currentData()

        if not algorithm_id or not framework_id:
            self.combo_key.addItem("No key available", None)
            return

        with app.app_context():
            keys = [
                key
                for key in KeyRepository.get_active()
                if key.algorithm_id == algorithm_id and key.framework_id == framework_id
            ]

        if not keys:
            self.combo_key.addItem("No matching key available", None)
            return

        for key in keys:
            self.combo_key.addItem(f"{key.name} [{key.key_type}]", key.id)

    def selected_entities(self):
        with app.app_context():
            managed_file = FileRepository.get_by_id(self.combo_files.currentData())
            algorithm = AlgorithmRepository.get_by_id(self.combo_alg.currentData())
            framework = FrameworkRepository.get_by_id(self.combo_fw.currentData())
            key_record = KeyRepository.get_by_id(self.combo_key.currentData())

        return managed_file, algorithm, framework, key_record

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")

        if file_path:
            self.selected_file_path = file_path
            self.file_label.setText(
                f"Selected local file:\n{os.path.basename(file_path)}\n\n{file_path}"
            )

    def register_file(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Warning", "Select a local file first.")
            return

        with app.app_context():
            managed_file = FileManagementService.register_file(self.selected_file_path)

        self.status_label.setText(
            f"Registered file: {managed_file.original_name}\nOriginal SHA-256 hash stored in DB."
        )

        self.selected_file_path = None
        self.file_label.setText("No local file selected.")
        self.load_data()

    def generate_key(self):
        algorithm_id = self.combo_alg.currentData()
        framework_id = self.combo_fw.currentData()

        if not algorithm_id or not framework_id:
            QMessageBox.warning(self, "Warning", "Select an algorithm and framework first.")
            return

        key_name, accepted = QInputDialog.getText(self, "Generate Key", "Key name:")

        if not accepted or not key_name.strip():
            return

        with app.app_context():
            algorithm = AlgorithmRepository.get_by_id(algorithm_id)
            framework = FrameworkRepository.get_by_id(framework_id)

            try:
                key_record = KeyManagementService.generate_key(
                    key_name.strip(),
                    algorithm,
                    framework,
                )
            except CryptoServiceError as exc:
                QMessageBox.critical(self, "Key Generation Error", str(exc))
                return

        self.status_label.setText(
            f"Generated key: {key_record.name}\nAlgorithm: {algorithm.name}\nFramework: {framework.name}"
        )

        self.load_data()

    def encrypt_file(self):
        self._run_crypto_operation("encrypt")

    def decrypt_file(self):
        self._run_crypto_operation("decrypt")

    def _run_crypto_operation(self, operation_type):
        managed_file, algorithm, framework, key_record = self.selected_entities()

        if not managed_file or not algorithm or not framework or not key_record:
            QMessageBox.warning(
                self,
                "Warning",
                "Select managed file, algorithm, framework and key first.",
            )
            return

        try:
            with app.app_context():
                if operation_type == "encrypt":
                    result = CryptoManagerService.encrypt_file(
                        managed_file,
                        algorithm,
                        framework,
                        key_record,
                    )
                else:
                    result = CryptoManagerService.decrypt_file(
                        managed_file,
                        algorithm,
                        framework,
                        key_record,
                    )

        except CryptoServiceError as exc:
            QMessageBox.critical(self, "Crypto Error", str(exc))
            self.status_label.setText(f"{operation_type.title()} failed:\n{exc}")
            self.load_data()
            return

        except Exception as exc:
            QMessageBox.critical(self, "Unexpected Error", str(exc))
            self.status_label.setText(f"{operation_type.title()} failed:\n{exc}")
            self.load_data()
            return

        performance = result.performance

        self.status_label.setText(
            f"{result.message}\n\n"
            f"Output: {result.output_path}\n"
            f"Time: {performance.execution_time_ms:.2f} ms\n"
            f"Memory: {performance.memory_usage_mb:.4f} MB"
        )

        QMessageBox.information(
            self,
            "Operation Complete",
            (
                f"{result.message}\n\n"
                f"Output path:\n{result.output_path}\n\n"
                f"Execution time: {performance.execution_time_ms:.2f} ms\n"
                f"Memory usage: {performance.memory_usage_mb:.4f} MB"
            ),
        )

        self.load_data()

    def show_keys_debug(self):
        with app.app_context():
            keys = KeyRepository.get_all()

        if not keys:
            self.details_box.setPlainText("No keys stored.")
            return

        lines = []

        for key in keys:
            value = getattr(key, "key_value", None)
            preview = value[:60] + "..." if value and len(value) > 60 else value

            lines.append(
                f"ID: {key.id}\n"
                f"Name: {key.name}\n"
                f"Algorithm ID: {key.algorithm_id}\n"
                f"Framework ID: {key.framework_id}\n"
                f"Type: {key.key_type}\n"
                f"Active: {key.is_active}\n"
                f"Value Preview: {preview or 'PEM / key pair stored separately'}\n"
                f"{'-' * 70}"
            )

        self.details_box.setPlainText("\n".join(lines))

    def refresh_details(self):
        with app.app_context():
            operations = OperationRepository.get_all()[:10]
            performances = PerformanceRepository.get_all()[:10]

            if self.combo_files.count():
                managed_file = FileRepository.get_by_id(self.combo_files.currentData())
            else:
                managed_file = None

        self._populate_operations_table(operations)
        self._populate_performance_table(performances)
        self._update_file_summary(managed_file)

    def _update_file_summary(self, managed_file):
        if not managed_file:
            self.metric_file_status.value_label.setText("No file")
            self.metric_hash_status.value_label.setText("Unknown")
            self.file_summary.setPlainText(
                "No managed file selected.\n\n"
                "Steps:\n"
                "1. Browse a local file.\n"
                "2. Register it into the local database.\n"
                "3. Select algorithm, framework and key.\n"
                "4. Run encryption or decryption."
            )
            return

        if managed_file.integrity_verified is True:
            hash_state = "Verified"
        elif managed_file.integrity_verified is False:
            hash_state = "Mismatch"
        else:
            hash_state = "Pending"

        self.metric_file_status.value_label.setText(managed_file.status.upper())
        self.metric_hash_status.value_label.setText(hash_state)

        self.file_summary.setPlainText(
            "\n".join(
                [
                    f"Name: {managed_file.original_name}",
                    f"Status: {managed_file.status}",
                    "",
                    f"Original path: {managed_file.original_path}",
                    f"Encrypted path: {managed_file.encrypted_path or '-'}",
                    f"Decrypted path: {managed_file.decrypted_path or '-'}",
                    "",
                    f"Original SHA-256: {managed_file.original_hash or '-'}",
                    f"Encrypted SHA-256: {managed_file.encrypted_hash or '-'}",
                    f"Decrypted SHA-256: {managed_file.decrypted_hash or '-'}",
                    "",
                    f"Integrity verified: {managed_file.integrity_verified}",
                    f"Created at: {managed_file.created_at}",
                    f"Updated at: {managed_file.updated_at}",
                ]
            )
        )

        cursor = self.file_summary.textCursor()
        cursor.movePosition(cursor.MoveOperation.Start)
        self.file_summary.setTextCursor(cursor)

    def _populate_operations_table(self, operations):
        self.operations_table.setRowCount(len(operations))

        for row, op in enumerate(operations):
            values = [
                str(op.id),
                op.operation_type,
                op.status,
                str(op.file_id),
                str(op.framework_id),
                str(op.started_at),
                op.error_message or "-",
            ]

            for col, value in enumerate(values):
                item = QTableWidgetItem(value)

                if col == 2:
                    self._color_status_item(item, value)

                self.operations_table.setItem(row, col, item)

    def _populate_performance_table(self, performances):
        self.performance_table.setRowCount(len(performances))

        for row, perf in enumerate(performances):
            values = [
                str(perf.operation_id),
                f"{perf.execution_time_ms:.2f}",
                f"{perf.memory_usage_mb:.4f}",
                str(perf.input_size_bytes),
                str(perf.output_size_bytes),
                str(perf.created_at),
            ]

            for col, value in enumerate(values):
                self.performance_table.setItem(row, col, QTableWidgetItem(value))

    def _color_status_item(self, item, status):
        normalized = status.lower()

        if normalized == "success":
            item.setForeground(QColor("#22c55e"))
        elif normalized == "failed":
            item.setForeground(QColor("#ef4444"))
        elif normalized == "running":
            item.setForeground(QColor("#f59e0b"))
        else:
            item.setForeground(QColor("#cbd5e1"))