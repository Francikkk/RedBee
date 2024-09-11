# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from exception_handler import ExceptionHandler
from core_functions import OpcUaClient, SmsSender, MailSender, SqlHandler
from constants import (
    INPUT_FORM_ERROR_BACKGROUND_COLOR,
    ERROR_TEXT_COLOR,
    OWN_CERTIFICATE_FILE_PATH,
    OWN_PRIVATE_KEY_FILE_PATH,
    MAIN_WINDOW_TITLE,
    MAIN_WINDOW_OPENING_POSITION,
    MAIN_WINDOW_SIZE,
    ICON_LOGO,
    MAIN_WINDOW_BACKGROUND_COLOR,
    MAIN_WINDOW_MENU_BAR_STYLE,
    INFO_WINDOW_TITLE,
    INFO_WINDOW_TEXT,
    INFO_WINDOW_STYLE,
    SETTING_WINDOW_TITLE,
    SETTING_WINDOW_OPENING_POSITION,
    SETTING_WINDOW_SIZE,
    ICON_GEAR,
    HISTORIAN_WINDOW_TITLE,
    HISTORIAN_WINDOW_OPENING_POSITION,
    HISTORIAN_WINDOW_SIZE,
    ICON_HISTORIAN,
    HISTORIAN_CSV_FILE_PATH,
    ICON_CSV_EXPORT,
    CERTIFICATE_HANDLER_WINDOW_TITLE,
    CERTIFICATE_HANDLER_WINDOW_OPENING_POSITION,
    CERTIFICATE_HANDLER_WINDOW_SIZE,
    ICON_CERTIFICATE,
    OWN_CERTIFICATE_FILE_PATH,
    OWN_PRIVATE_KEY_FILE_PATH,
    ICON_RELOAD,
    ICON_DIRECTORY,
    USER_WINDOW_TITLE,
    USER_WINDOW_OPENING_POSITION,
    USER_WINDOW_SIZE,
    ICON_USER,
    ICON_ADD_USER,
    ICON_REMOVE_USER,
    ICON_ADD_ROLE,
    ICON_REMOVE_ROLE,
    AUTH_FILE,
    LICENSE_WINDOW_TITLE,
    LICENSE_WINDOW_OPENING_POSITION,
    LICENSE_WINDOW_MARGINS,
    LICENSE_WINDOW_SIZE_IF_ACTIVATED,
    LICENSE_WINDOW_SIZE_IF_NOT_ACTIVATED,
    LICENSE_SUBSCRIPTION_LIST,
    LICENSE_DURATION_LIST,
    LICENSE_ACTIVATION_WINDOW_TITLE,
    LICENSE_ACTIVATION_WINDOW_OPENING_POSITION,
    LICENSE_ACTIVATION_WINDOW_SIZE,
    LICENSE_UPDATE_WINDOW_TITLE,
    LICENSE_UPDATE_WINDOW_OPENING_POSITION,
    LICENSE_UPDATE_WINDOW_SIZE,
    MAIN_WIDGET_TITLE,
    ICON_FULL_LOGO,
    MAIN_WIDGET_TEXT_COLOR,
    ICON_CERTIFICATE,
    ICON_HISTORIAN,
    ICON_USER,
    ICON_GEAR,
    MAIN_WIDGET_BUTTON_CONNECT_COLOR,
    MAIN_WIDGET_BUTTON_DISCONNECT_COLOR,
    ROUND_INDICATOR_SIZE,
    INFO_MESSAGE_SIZE,
    INFO_MESSAGE_POSITION,
    CERTIFICATE_PKI_DIRECTORY,
)

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
import pandas as pd
import datetime
import os
import re
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QCheckBox,
    QTabWidget,
    QFileDialog,
    QComboBox,
    QToolButton,
    QDialog,
    QTableView,
    QMainWindow,
    QGridLayout,
    QTableWidget, 
    QTableWidgetItem,
    QSizePolicy,
    QHeaderView,
    QAbstractItemView,
)
from PySide6.QtGui import (
    QPixmap,
    QIcon,
    QPainter,
    QBrush,
    QStandardItemModel,
    QStandardItem,
    QPalette,
    QPen,
    QAction,
    QColor,
)
from PySide6.QtCore import Qt


# -------------------------------------------------#
#                  User Interface                  #
# -------------------------------------------------#
# ---------------------Windows---------------------#
# Main window for the user interface
class MainUI(QMainWindow):
    def __init__(self, core):
        super().__init__()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: initializing.."
        )
        self.core = core
        self.initUI()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: created!"
        )

    def initUI(self):
        self.setWindowTitle(MAIN_WINDOW_TITLE)
        self.setGeometry(*MAIN_WINDOW_OPENING_POSITION, *MAIN_WINDOW_SIZE)
        self.setMinimumSize(*MAIN_WINDOW_SIZE)
        self.setWindowIcon(QIcon(ICON_LOGO))

        # Create the central widget and set it
        self.main_widget = MainWidget(self.core)
        self.setCentralWidget(self.main_widget)

        self.setStyleSheet(MAIN_WINDOW_BACKGROUND_COLOR)

        # Create the menu bar
        self.createMenuBar()

    def createMenuBar(self):
        menu_bar = self.menuBar()

        # Set the stylesheet for the menu bar and menus
        menu_bar.setStyleSheet(MAIN_WINDOW_MENU_BAR_STYLE)

        # File Menu
        file_menu = menu_bar.addMenu("File")
        if self.core.auth_handler.active_user:
            if (
                "Save configuration"
                in self.core.auth_handler.roles[self.core.auth_handler.get_user_role()][
                    "Main"
                ]
            ):
                save_action = QAction("Save Configuration", self)
                save_action.triggered.connect(self.save_configuration)
                file_menu.addAction(save_action)
            if (
                "Load configuration"
                in self.core.auth_handler.roles[self.core.auth_handler.get_user_role()][
                    "Main"
                ]
            ):
                load_action = QAction("Load Configuration", self)
                load_action.triggered.connect(self.load_configuration)
                file_menu.addAction(load_action)
            exit_action = QAction("Exit", self)
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)
        else:
            save_action = QAction("Save Configuration", self)
            save_action.triggered.connect(self.save_configuration)
            file_menu.addAction(save_action)
            load_action = QAction("Load Configuration", self)
            load_action.triggered.connect(self.load_configuration)
            file_menu.addAction(load_action)
            exit_action = QAction("Exit", self)
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

        # Edit Menu
        edit_menu = menu_bar.addMenu("Edit")
        settings_action = None
        user_action = None
        certificate_handler_action = None
        if self.core.auth_handler.active_user:
            if (
                self.core.auth_handler.roles[self.core.auth_handler.get_user_role()][
                    "Settings"
                ]
                != []
            ):
                settings_action = QAction("Settings", self)
                settings_action.triggered.connect(self.show_settings)
                edit_menu.addAction(settings_action)
            if (
                "View user window"
                in self.core.auth_handler.roles[self.core.auth_handler.get_user_role()][
                    "User_manager"
                ]
            ):
                user_action = QAction("User Management", self)
                user_action.triggered.connect(self.access_management)
                edit_menu.addAction(user_action)
            if (
                "View certificate window"
                in self.core.auth_handler.roles[self.core.auth_handler.get_user_role()][
                    "Certificate"
                ]
            ):
                certificate_handler_action = QAction("Certificate Handler", self)
                certificate_handler_action.triggered.connect(self.certificate_handler)
                edit_menu.addAction(certificate_handler_action)
            if (
                settings_action is None
                and user_action is None
                and certificate_handler_action is None
            ):
                menu_bar.removeAction(edit_menu.menuAction())
        else:
            settings_action = QAction("Settings", self)
            settings_action.triggered.connect(self.show_settings)
            edit_menu.addAction(settings_action)
            user_action = QAction("User Management", self)
            user_action.triggered.connect(self.access_management)
            edit_menu.addAction(user_action)
            certificate_handler_action = QAction("Certificate Handler", self)
            certificate_handler_action.triggered.connect(self.certificate_handler)
            edit_menu.addAction(certificate_handler_action)

        # Analysis Menu
        analysis_menu = menu_bar.addMenu("Analysis")
        if self.core.auth_handler.active_user:
            if (
                "View alarm log window"
                in self.core.auth_handler.roles[self.core.auth_handler.get_user_role()][
                    "Alarm Log"
                ]
            ):
                event_historian_action = QAction("Event Historian", self)
                event_historian_action.triggered.connect(self.event_historian)
                analysis_menu.addAction(event_historian_action)
            else:
                menu_bar.removeAction(analysis_menu.menuAction())
        else:
            event_historian_action = QAction("Event Historian", self)
            event_historian_action.triggered.connect(self.event_historian)
            analysis_menu.addAction(event_historian_action)

        # About Menu
        about_menu = menu_bar.addMenu("About")
        info_action = QAction("Info", self)
        info_action.triggered.connect(self.show_info)
        about_menu.addAction(info_action)
        license_action = QAction("License", self)
        license_action.triggered.connect(self.license)
        about_menu.addAction(license_action)

    def save_configuration(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: Save configuration"
        )
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save Configuration",
            "",
            "Config Files (*.json);;All Files (*)",
            options=options,
        )
        if file_name:
            print(f"Configuration saved to {file_name}")

    def load_configuration(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: Load configuration"
        )
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Load Configuration",
            "",
            "Config Files (*.json);;All Files (*)",
            options=options,
        )
        if file_name:
            print(f"Configuration loaded from {file_name}")

    def show_settings(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: Settings"
        )
        # Implement settings logic here
        try:
            settings_window = SettingsWindow(self.core.setting_manager)
            settings_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "SettingsWindow", "Error", QMessageBox.Critical
            )

    def access_management(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: User Management"
        )
        try:
            user_window = UserWindow(self.core.auth_handler)
            user_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "UserWindow", "Error", QMessageBox.Critical
            )

    def certificate_handler(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: Certificate Handler"
        )
        try:
            self.cert_handler_window = CertHandlerWindow(self.core)
            self.cert_handler_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "CertHandlerWindow", "Error", QMessageBox.Critical
            )

    def event_historian(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: Event Historian"
        )
        try:
            historian_window = HistorianWindow(self.core.auth_handler)
            historian_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "HistorianWindow", "Error", QMessageBox.Critical
            )

    def show_info(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: Info"
        )
        msg_box = QMessageBox()
        msg_box.setWindowTitle(INFO_WINDOW_TITLE)
        msg_box.setText(INFO_WINDOW_TEXT)
        msg_box.setStyleSheet(INFO_WINDOW_STYLE)
        msg_box.exec()

    def license(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: License"
        )
        try:
            license_window = LicenseWindow(self.core.info_manager.license_manager)
            license_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "LicenseWindow", "Error", QMessageBox.Critical
            )


# Settings window for the user interface
class SettingsWindow(QDialog):
    def __init__(self, setting_manager):
        super().__init__()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: initializing.."
        )
        self.setting_manager = setting_manager
        self.current_user = None
        self.current_role = None
        if self.setting_manager.auth_handler.active_user:
            self.current_user = self.setting_manager.auth_handler.active_user
            self.current_role = self.setting_manager.auth_handler.get_user_role()
        self.initUI()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainUI: created!"
        )

    def initUI(self):
        self.setWindowTitle(SETTING_WINDOW_TITLE)
        self.setGeometry(*SETTING_WINDOW_OPENING_POSITION, *SETTING_WINDOW_SIZE)
        self.setMinimumSize(*SETTING_WINDOW_SIZE)

        self.setWindowIcon(QIcon(ICON_GEAR))

        self.tab_widget = QTabWidget()
        self.general_settings_widget = GeneralSettingsWidget(self.setting_manager)
        self.opc_settings_widget = OPCSettingsWidget(self.setting_manager)
        self.alarm_subscription_widget = AlarmSubscriptionWidget(self.setting_manager)
        self.twilio_settings_widget = TwilioSettingsWidget(self.setting_manager)
        self.smtp_settings_widget = SMTPSettingsWidget(self.setting_manager)
        # self.sql_settings_widget = SQLSettingsWidget(self.setting_manager)

        if self.current_role:
            if (
                "General"
                in self.setting_manager.auth_handler.roles[self.current_role][
                    "Settings"
                ]
            ):
                self.tab_widget.addTab(self.general_settings_widget, "General")
            if (
                "OPC"
                in self.setting_manager.auth_handler.roles[self.current_role][
                    "Settings"
                ]
            ):
                self.tab_widget.addTab(self.opc_settings_widget, "OPC Settings")
            if (
                "Alarm"
                in self.setting_manager.auth_handler.roles[self.current_role][
                    "Settings"
                ]
            ):
                self.tab_widget.addTab(
                    self.alarm_subscription_widget, "Alarm Subscription"
                )
            if (
                "Twilio"
                in self.setting_manager.auth_handler.roles[self.current_role][
                    "Settings"
                ]
            ):
                self.tab_widget.addTab(self.twilio_settings_widget, "Twilio")
            if (
                "SMTP"
                in self.setting_manager.auth_handler.roles[self.current_role][
                    "Settings"
                ]
            ):
                self.tab_widget.addTab(self.smtp_settings_widget, "SMTP")
            # if "SQL" in self.setting_manager.auth_handler.roles[self.current_role]["Settings"]:
            #     self.tab_widget.addTab(self.sql_settings_widget, 'SQL Settings
        else:
            self.tab_widget.addTab(self.general_settings_widget, "General")
            self.tab_widget.addTab(self.opc_settings_widget, "OPC Settings")
            self.tab_widget.addTab(self.alarm_subscription_widget, "Alarm Subscription")
            self.tab_widget.addTab(self.twilio_settings_widget, "Twilio")
            self.tab_widget.addTab(self.smtp_settings_widget, "SMTP")
            # self.tab_widget.addTab(self.sql_settings_widget, 'SQL Settings')

        layout = QVBoxLayout()
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)


# Historian Window for the user interface
class HistorianWindow(QDialog):
    def __init__(self, auth_handler):
        super().__init__()
        self.auth_handler = auth_handler
        self.current_user = None
        self.current_role = None
        if self.auth_handler.active_user:
            self.current_user = self.auth_handler.active_user
            self.current_role = self.auth_handler.get_user_role()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(HISTORIAN_WINDOW_TITLE)
        self.setGeometry(*HISTORIAN_WINDOW_OPENING_POSITION, *HISTORIAN_WINDOW_SIZE)
        self.setMinimumSize(*HISTORIAN_WINDOW_SIZE)
        self.setWindowIcon(QIcon(ICON_HISTORIAN))
        # Read dataframe from CSV file
        try:
            df = pd.read_csv(HISTORIAN_CSV_FILE_PATH, delimiter=";")
        except FileNotFoundError:
            ExceptionHandler.handle_exception(
                "File not found", "HistorianWidget", "Error", QMessageBox.Critical
            )
            df = pd.DataFrame()
        # Create a QStandardItemModel to hold DataFrame data
        model = QStandardItemModel(df.shape[0], df.shape[1])
        model.setHorizontalHeaderLabels(df.columns)
        # Fill model with DataFrame data
        for i in range(df.shape[0]):
            for j in range(df.shape[1]):
                item = QStandardItem(str(df.iat[i, j]))
                item.setEditable(False)
                item.setTextAlignment(Qt.AlignCenter)
                model.setItem(i, j, item)

        # Create TableView to display DataFrame
        table_view = QTableView()
        table_view.setModel(model)
        table_view.setEditTriggers(QTableView.NoEditTriggers)
        table_view.setColumnHidden(0, True)
        table_view.setColumnHidden(5, True)
        # table_view.setColumnHidden(6, True)
        table_view.setColumnHidden(7, True)
        table_view.resizeColumnsToContents()
        table_view.setSelectionBehavior(QTableView.SelectRows)
        table_view.setSelectionMode(QTableView.SingleSelection) 

        # create a button to export the data to a CSV file
        self.export_button = QToolButton()
        self.export_button.setIcon(QIcon(ICON_CSV_EXPORT))
        self.export_button.setToolTip("Export data to .csv")
        self.export_button.clicked.connect(self.export_data)

        # Create a horizontal layout for the button
        h_layout = QHBoxLayout()
        h_layout.addStretch()
        h_layout.addWidget(self.export_button)

        # Main layout
        layout = QVBoxLayout()
        layout.addWidget(table_view)
        if self.current_role:
            if (
                "Export alarm log"
                in self.auth_handler.roles[self.current_role]["Alarm Log"]
            ):
                layout.addLayout(h_layout)
        else:
            layout.addLayout(h_layout)
        self.setLayout(layout)

    def export_data(self):
        try:
            df = pd.read_csv(HISTORIAN_CSV_FILE_PATH, delimiter=";")
        except FileNotFoundError:
            ExceptionHandler.handle_exception(
                "File not found", "HistorianWidget", "Error", QMessageBox.Critical
            )
            df = pd.DataFrame()
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Export Data", "", "CSV Files (*.csv);;All Files (*)", options=options
        )
        if file_name:
            df.to_csv(file_name, sep=";", index=False)
            print(f"Data exported to {file_name}")


# Certificate Handler Window for the user interface
class CertHandlerWindow(QDialog):
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.auth_handler = self.core.info_manager.setting_manager.auth_handler
        self.current_user = None
        self.current_role = None
        if self.auth_handler.active_user:
            self.current_user = self.auth_handler.active_user
            self.current_role = self.auth_handler.get_user_role()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(CERTIFICATE_HANDLER_WINDOW_TITLE)
        self.setGeometry(
            *CERTIFICATE_HANDLER_WINDOW_OPENING_POSITION,
            *CERTIFICATE_HANDLER_WINDOW_SIZE,
        )
        self.setMinimumSize(*CERTIFICATE_HANDLER_WINDOW_SIZE)
        self.setWindowIcon(QIcon(ICON_CERTIFICATE))
    
        # Read certificate from file
        try:
            with open(OWN_CERTIFICATE_FILE_PATH, "rb") as file:
                cert = x509.load_pem_x509_certificate(file.read())
        except FileNotFoundError:
            ExceptionHandler.handle_exception(
                "File not found", "CertHandlerWindow", "Error", QMessageBox.Critical
            )
            cert = None
    
        # Read private key from file
        try:
            with open(OWN_PRIVATE_KEY_FILE_PATH, "rb") as file:
                private_key = serialization.load_pem_private_key(
                    file.read(), password=None
                )
        except FileNotFoundError:
            ExceptionHandler.handle_exception(
                "File not found", "CertHandlerWindow", "Error", QMessageBox.Critical
            )
            private_key = None
    
        # Create a QStandardItemModel to hold certificate data
        self.model = QStandardItemModel(5, 2)
        self.model.setHorizontalHeaderLabels(["Field", "Value"])
        
        # Function to create centered QStandardItem
        def centered_item(text):
            item = QStandardItem(text)
            item.setTextAlignment(Qt.AlignCenter)
            return item

        # Fill model with certificate data
        self.model.setItem(0, 0, centered_item("Issuer"))
        self.model.setItem(0, 1, centered_item(str(cert.issuer.rfc4514_string())))
        self.model.setItem(1, 0, centered_item("Subject"))
        self.model.setItem(1, 1, centered_item(str(cert.subject.rfc4514_string())))
        self.model.setItem(2, 0, centered_item("Serial Number"))
        self.model.setItem(2, 1, centered_item(str(cert.serial_number)))
        self.model.setItem(3, 0, centered_item("Valid from"))
        self.model.setItem(3, 1, centered_item(str(cert.not_valid_before)))
        self.model.setItem(4, 0, centered_item("Expiration"))
        self.model.setItem(4, 1, centered_item(str(cert.not_valid_after)))
    
        # Create TableView to display certificate data
        table_view = QTableView()
        table_view.setModel(self.model)
        table_view.setEditTriggers(QTableView.NoEditTriggers)
        table_view.resizeColumnsToContents()
    
        # Hide headers
        table_view.horizontalHeader().hide()
        table_view.verticalHeader().hide()
    
        # Remove grid lines
        table_view.setShowGrid(False)
        table_view.setGridStyle(Qt.NoPen)
    
        table_view.setSelectionBehavior(QTableView.SelectRows)
        table_view.setSelectionMode(QTableView.SingleSelection) 
    
        # Regenerate certificate button
        self.regenerate_button = QToolButton()
        self.regenerate_button.setIcon(QIcon(ICON_RELOAD))
        self.regenerate_button.setToolTip("Regenerate certificate")
        self.regenerate_button.clicked.connect(self.regenerate_certificate)
    
        # Directory button
        self.directory_button = QToolButton()
        self.directory_button.setIcon(QIcon(ICON_DIRECTORY))
        self.directory_button.setToolTip("Open certificate directory")
        self.directory_button.clicked.connect(self.open_certificate_directory)
    
        # Status layout with settings button aligned to the right
        if self.current_role:
            button_layout = QHBoxLayout()
            button_layout.addStretch()
            if (
                "Regenerate certificate"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Certificate"]
            ):
                button_layout.addWidget(self.regenerate_button)
            if (
                "Open certificate location"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Certificate"]
            ):
                button_layout.addWidget(self.directory_button)
        else:
            button_layout = QHBoxLayout()
            button_layout.addStretch()
            button_layout.addWidget(self.regenerate_button)
            button_layout.addWidget(self.directory_button)
    
        # Layout
        layout = QVBoxLayout()
        layout.addWidget(table_view)
        layout.addStretch()
        layout.addLayout(button_layout)
    
        self.setLayout(layout)

    def update_ui(self):
        try:
            with open(OWN_CERTIFICATE_FILE_PATH, "rb") as file:
                cert = x509.load_pem_x509_certificate(file.read())
        except FileNotFoundError:
            ExceptionHandler.handle_exception(
                "File not found", "CertHandlerWindow", "Error", QMessageBox.Critical
            )
            cert = None
        self.model.setItem(0, 0, QStandardItem("Issuer"))
        self.model.setItem(0, 1, QStandardItem(str(cert.issuer.rfc4514_string())))
        self.model.setItem(1, 0, QStandardItem("Subject"))
        self.model.setItem(1, 1, QStandardItem(str(cert.subject.rfc4514_string())))
        self.model.setItem(2, 0, QStandardItem("Serial Number"))
        self.model.setItem(2, 1, QStandardItem(str(cert.serial_number)))
        self.model.setItem(3, 0, QStandardItem("Not Before"))
        self.model.setItem(3, 1, QStandardItem(str(cert.not_valid_before)))
        self.model.setItem(4, 0, QStandardItem("Not After"))
        self.model.setItem(4, 1, QStandardItem(str(cert.not_valid_after)))
        self.model.layoutChanged.emit()

    def open_certificate_directory(self):
        try:
            os.startfile(os.getcwd() + CERTIFICATE_PKI_DIRECTORY)
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "CertHandlerWindow", "Error", QMessageBox.Critical
            )

    def regenerate_certificate(self):
        try:
            self.core.info_manager.cert_handler.regenerate()
            self.update_ui()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
        else:
            QMessageBox.information(
                self, "Success", "Certificate regenerated successfully"
            )


# User Window for the user interface
class UserWindow(QDialog):
    def __init__(self, auth_handler):
        super().__init__()
        self.auth_handler = auth_handler
        self.current_user = None
        self.current_role = None
        if self.auth_handler.active_user:
            self.current_user = self.auth_handler.active_user
            self.current_role = self.auth_handler.get_user_role()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(USER_WINDOW_TITLE)
        self.setGeometry(*USER_WINDOW_OPENING_POSITION, *USER_WINDOW_SIZE)
        self.setMinimumSize(*USER_WINDOW_SIZE)
        self.setWindowIcon(QIcon(ICON_USER))

        self.table_view = QTableView()
        self.table_view.setShowGrid(False)  # Hide grid lines

        # Set selection behavior to select entire rows
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)  # or MultiSelection for multi-row selection

        # Resize columns
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_view.setColumnWidth(0, 150)  # Adjust width for Username column
        self.table_view.setColumnWidth(1, 150)  # Adjust width for Role column
        self.table_view.setColumnWidth(2, 150)  # Adjust width for Domain column

        self.add_user_button = QToolButton()
        self.add_user_button.setIcon(QIcon(ICON_ADD_USER))
        self.add_user_button.setToolTip("Add user")
        self.add_user_button.clicked.connect(self.add_user)

        self.remove_user_button = QToolButton()
        self.remove_user_button.setIcon(QIcon(ICON_REMOVE_USER))
        self.remove_user_button.setToolTip("Remove user")
        self.remove_user_button.clicked.connect(self.remove_user)

        self.add_roles_button = QToolButton()
        self.add_roles_button.setIcon(QIcon(ICON_ADD_ROLE))
        self.add_roles_button.setToolTip("Add roles")
        self.add_roles_button.clicked.connect(self.add_role)

        self.remove_roles_button = QToolButton()
        self.remove_roles_button.setIcon(QIcon(ICON_REMOVE_ROLE))
        self.remove_roles_button.setToolTip("Remove roles")
        self.remove_roles_button.clicked.connect(self.remove_role)

        button_layout = QHBoxLayout()
        if self.current_role:
            button_layout.addStretch()
            if (
                "Remove role"
                in self.auth_handler.roles[self.current_role]["User_manager"]
            ):
                button_layout.addWidget(self.remove_roles_button)
            if "Add role" in self.auth_handler.roles[self.current_role]["User_manager"]:
                button_layout.addWidget(self.add_roles_button)
            if (
                "Remove user"
                in self.auth_handler.roles[self.current_role]["User_manager"]
            ):
                button_layout.addWidget(self.remove_user_button)
            if "Add user" in self.auth_handler.roles[self.current_role]["User_manager"]:
                button_layout.addWidget(self.add_user_button)
        else:
            button_layout.addStretch()
            button_layout.addWidget(self.remove_roles_button)
            button_layout.addWidget(self.add_roles_button)
            button_layout.addWidget(self.remove_user_button)
            button_layout.addWidget(self.add_user_button)

        layout = QVBoxLayout()
        layout.addWidget(self.table_view)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.refresh_model()

    def refresh_model(self):
        try:
            with open(AUTH_FILE, "r") as file:
                data = json.load(file)
                users = data.get("users", {})
        except FileNotFoundError:
            ExceptionHandler.handle_exception(
                "File not found", "UserWindow", "Error", QMessageBox.Critical
            )
            users = {}  # Empty dict if file not found
        except json.JSONDecodeError as e:
            ExceptionHandler.handle_exception(
                f"JSON decode error: {e}", "UserWindow", "Error", QMessageBox.Critical
            )
            users = {}  # Empty dictionary if JSON is invalid

        self.model = QStandardItemModel(len(users), 3)
        self.model.setHorizontalHeaderLabels(["Username", "Role", "Domain"])
        for i, (username, user_data) in enumerate(users.items()):
            role = user_data.get("role", "Unknown")
            domain = user_data.get("domain", "RedBee")
            username_item = QStandardItem(username)
            role_item = QStandardItem(role)
            domain_item = QStandardItem(domain)
            username_item.setTextAlignment(Qt.AlignCenter)
            role_item.setTextAlignment(Qt.AlignCenter)
            domain_item.setTextAlignment(Qt.AlignCenter)
            self.model.setItem(i, 0, username_item)
            self.model.setItem(i, 1, role_item)
            self.model.setItem(i, 2, domain_item)

        self.table_view.setModel(self.model)
        self.table_view.setEditTriggers(QTableView.NoEditTriggers)
        self.table_view.resizeColumnsToContents()
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)

    def add_user(self):
        self.auth_handler.show_add_user_dialog(self)
        self.refresh_model()

    def remove_user(self):
        self.auth_handler.show_remove_user_dialog(self)
        self.refresh_model()

    def add_role(self):
        self.auth_handler.show_add_role_dialog(self)
        self.refresh_model()

    def remove_role(self):
        self.auth_handler.show_remove_role_dialog(self)
        self.refresh_model()


# License info windows for the user interface
class LicenseWindow(QDialog):
    def __init__(self, license_manager):
        super().__init__()
        self.license_manager = license_manager
        self.initUI()

    def initUI(self):
        self.setWindowTitle(LICENSE_WINDOW_TITLE)
        self.setWindowIcon(QIcon(ICON_LOGO))
    
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(*LICENSE_WINDOW_MARGINS)  # Add margins

        if self.license_manager.hidden_info:
            self.setGeometry(*LICENSE_WINDOW_OPENING_POSITION, *LICENSE_WINDOW_SIZE_IF_ACTIVATED)
            self.setMinimumSize(*LICENSE_WINDOW_SIZE_IF_ACTIVATED)
            
            # Create a QTableWidget to hold the labels and values
            table_widget = QTableWidget()
            table_widget.setRowCount(8)  # Number of rows
            table_widget.setColumnCount(2)  # Two columns: Label and Value
            
            # Remove table headers and index numbers
            table_widget.horizontalHeader().setVisible(False)
            table_widget.verticalHeader().setVisible(False)
            table_widget.setShowGrid(False)  # Optional: remove grid lines

            # Set table values
            fields = [
                "First Name", "Last Name", "Email", "Company", 
                "Address", "Serial Number", "Activation Status", "Expiration Date"
            ]
            values = [
                self.license_manager.hidden_info['first_name'],
                self.license_manager.hidden_info['last_name'],
                self.license_manager.hidden_info['email'],
                self.license_manager.hidden_info['company'],
                self.license_manager.hidden_info['reference_address'],
                self.license_manager.hidden_info['serial_number'],
                self.license_manager.activation_status,
                self.license_manager.hidden_info['expiration_date']
            ]
            
            for row, (field, value) in enumerate(zip(fields, values)):
                table_widget.setItem(row, 0, QTableWidgetItem(field))
                table_widget.setItem(row, 1, QTableWidgetItem(value))
            
            table_widget.resizeColumnsToContents()
            table_widget.resizeRowsToContents()
            table_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)  # Adjust size policy

            # Create a centered layout for the table
            table_layout = QHBoxLayout()
            table_layout.addStretch(1)
            table_layout.addWidget(table_widget)
            table_layout.addStretch(1)

            main_layout.addLayout(table_layout)

            # Add buttons at the bottom
            button_layout = QHBoxLayout()
            button_layout.setContentsMargins(0, 10, 0, 0)  # Add margins only at the top

            self.update_button = QPushButton("Update License")
            self.update_button.clicked.connect(self.update_license)
            button_layout.addWidget(self.update_button)
            
            self.change_button = QPushButton("Change License")
            self.change_button.clicked.connect(self.change_license)
            button_layout.addWidget(self.change_button)
            
            main_layout.addLayout(button_layout)
            self.setLayout(main_layout)
        else:
            self.setGeometry(*LICENSE_WINDOW_OPENING_POSITION, *LICENSE_WINDOW_SIZE_IF_NOT_ACTIVATED)
            self.setMinimumSize(*LICENSE_WINDOW_SIZE_IF_NOT_ACTIVATED)
            
            self.alternative_text = QLabel(
                "RedBee not activated! Running in demo version.\n\nGet in touch with us or check our licensing tiers on www.RedBee.net"
            )
    
            # Activate button
            self.activate_button = QPushButton("Activate")
            self.activate_button.clicked.connect(self.activate)
            button_palette = self.activate_button.palette()
            button_palette.setColor(QPalette.ButtonText, Qt.black)
            self.activate_button.setPalette(button_palette)
    
            main_layout.addWidget(self.alternative_text)
            main_layout.addWidget(self.activate_button)
            self.setLayout(main_layout)

    def activate(self):
        activation_window = LicenseActivationWindow(self.license_manager, False)
        activation_window.exec()
        self.close()

    def update_license(self):
        activation_window = LicenseUpdateWindow(self.license_manager)
        activation_window.exec()
        self.close()

    def change_license(self):
        activation_window = LicenseActivationWindow(self.license_manager, True)
        activation_window.exec()
        self.close()


class LicenseActivationWindow(QDialog):
    def __init__(self, license_manager, lic_change=False):
        super().__init__()
        self.license_manager = license_manager
        self.lic_change = lic_change
        self.initUI()

    def initUI(self):
        self.setWindowTitle(LICENSE_ACTIVATION_WINDOW_TITLE)
        self.setWindowIcon(QIcon(ICON_LOGO))
        self.setGeometry(*LICENSE_ACTIVATION_WINDOW_OPENING_POSITION, *LICENSE_ACTIVATION_WINDOW_SIZE)
        self.setMinimumSize(*LICENSE_ACTIVATION_WINDOW_SIZE)

        layout = QGridLayout()

        self.plan_label = QLabel("*Subscription plan:       ")
        self.plan_combo = QComboBox()
        self.plan_combo.addItems(LICENSE_SUBSCRIPTION_LIST)
        layout.addWidget(self.plan_label, 0, 0)
        layout.addWidget(self.plan_combo, 0, 1)

        self.duration_label = QLabel("*Duration:")
        self.duration_combo = QComboBox()
        self.duration_combo.addItems(LICENSE_DURATION_LIST)
        layout.addWidget(self.duration_label, 1, 0)
        layout.addWidget(self.duration_combo, 1, 1)

        self.first_name_label = QLabel("*First Name:")
        self.first_name_input = QLineEdit()
        layout.addWidget(self.first_name_label, 2, 0)
        layout.addWidget(self.first_name_input, 2, 1)

        self.last_name_label = QLabel("*Last Name:")
        self.last_name_input = QLineEdit()
        layout.addWidget(self.last_name_label, 3, 0)
        layout.addWidget(self.last_name_input, 3, 1)

        self.email_label = QLabel("*Email:")
        self.email_input = QLineEdit()
        layout.addWidget(self.email_label, 4, 0)
        layout.addWidget(self.email_input, 4, 1)

        self.phone_label = QLabel("*Phone:")
        self.phone_input = QLineEdit()
        layout.addWidget(self.phone_label, 5, 0)
        layout.addWidget(self.phone_input, 5, 1)

        self.company_label = QLabel("Company:")
        self.company_input = QLineEdit()
        layout.addWidget(self.company_label, 6, 0)
        layout.addWidget(self.company_input, 6, 1)

        self.address_label = QLabel("Address:")
        self.address_input = QLineEdit()
        layout.addWidget(self.address_label, 7, 0)
        layout.addWidget(self.address_input, 7, 1)

        self.serial_number_label = QLabel("Serial Number:")
        self.serial_number_input = QLineEdit()
        layout.addWidget(self.serial_number_label, 8, 0)
        layout.addWidget(self.serial_number_input, 8, 1)

        self.license_key_label = QLabel("*License Key:")
        self.license_key_input = QLineEdit()
        layout.addWidget(self.license_key_label, 9, 0)
        layout.addWidget(self.license_key_input, 9, 1)

        self.activate_button = QPushButton("Activate")
        self.activate_button.clicked.connect(self.activate)
        button_palette = self.activate_button.palette()
        button_palette.setColor(QPalette.ButtonText, Qt.black)
        self.activate_button.setPalette(button_palette)

        layout.addWidget(self.activate_button, 10, 1)
        self.setLayout(layout)

    def activate(self):
        first_name = self.first_name_input.text()
        last_name = self.last_name_input.text()
        email = self.email_input.text()
        phone = self.phone_input.text()
        company = self.company_input.text()
        address = self.address_input.text()
        serial_number = self.serial_number_input.text()
        license_key = self.license_key_input.text()
        plan = self.plan_combo.currentText()
        duration = self.duration_combo.currentText()

        if not first_name or not last_name or not email or not phone or not license_key:
            QMessageBox.critical(self, "Error", "Please fill in all required fields")
            return

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            QMessageBox.critical(self, "Error", "Invalid email")
            return

        # if not phone.isdigit() or not re.match(r"^\+?(\d[\d-. ]?){10,15}$", phone):
        #     QMessageBox.critical(self, "Error", "Invalid phone number")
        #     return

        if not serial_number:
            serial_number = "N/A"

        if not address:
            address = "N/A"

        if not company:
            company = "N/A"

        if plan == "Professional":
            if duration == "1 year":
                duration = 1
            elif duration == "3 years":
                duration = 3
            elif duration == "5 years":
                duration = 5
        elif plan == "Enterprise":
            if duration == "1 year":
                duration = 1
            elif duration == "3 years":
                duration = 3
            elif duration == "5 years":
                duration = 5

        activation_result = self.license_manager.activate_license(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            company=company,
            reference_address=address,
            serial_number=serial_number,
            license_key=license_key,
            subscription_plan=plan,
            duration_years=duration,
            license_revision=0,
            license_change=self.lic_change,
        )
        self.lic_change = False
        if activation_result == "Already used":
            QMessageBox.critical(self, "Error Activating License", "The license key has already been used or has expired. Please contact RedBee support for assistance.")
        elif activation_result == "Invalid":
            QMessageBox.critical(self, "Error Activating License", "The license key is invalid. Please check the key and try again, or contact RedBee support for assistance.")
        elif activation_result == "Failed to delete old license":
            QMessageBox.critical(self, "Error Activating License", "Failed to renew license. Please contact RedBee support for assistance.")
            self.close()
        elif activation_result == "License changed":
            QMessageBox.information(self, "License modified", "License activated successfully.")
            self.close()
        elif activation_result == "License activated":
            QMessageBox.information(self, "License activated", "License activated successfully.")
            self.close()

class LicenseUpdateWindow(QDialog):
    def __init__(self, license_manager):
        super().__init__()
        self.license_manager = license_manager
        self.initUI()

    def initUI(self):
        self.setWindowTitle(LICENSE_UPDATE_WINDOW_TITLE)
        self.setWindowIcon(QIcon(ICON_LOGO))
        self.setGeometry(*LICENSE_UPDATE_WINDOW_OPENING_POSITION, *LICENSE_UPDATE_WINDOW_SIZE)
        self.setMinimumSize(*LICENSE_UPDATE_WINDOW_SIZE)

        layout = QGridLayout()

        self.plan_label = QLabel("*Subscription plan:       ")
        self.plan_combo = QComboBox()
        self.plan_combo.addItems(LICENSE_SUBSCRIPTION_LIST)
        layout.addWidget(self.plan_label, 0, 0)
        layout.addWidget(self.plan_combo, 0, 1)

        self.duration_label = QLabel("*Duration:")
        self.duration_combo = QComboBox()
        self.duration_combo.addItems(LICENSE_DURATION_LIST)
        layout.addWidget(self.duration_label, 1, 0)
        layout.addWidget(self.duration_combo, 1, 1)

        self.license_key_label = QLabel("*License Key:")
        self.license_key_input = QLineEdit()
        layout.addWidget(self.license_key_label, 2, 0)
        layout.addWidget(self.license_key_input, 2, 1)

        self.activate_button = QPushButton("Activate")
        self.activate_button.clicked.connect(self.activate)
        button_palette = self.activate_button.palette()
        button_palette.setColor(QPalette.ButtonText, Qt.black)
        self.activate_button.setPalette(button_palette)

        layout.addWidget(self.activate_button, 4, 1)
        self.setLayout(layout)

    def activate(self):
        first_name = self.license_manager.hidden_info['first_name']
        last_name = self.license_manager.hidden_info['last_name']
        email = self.license_manager.hidden_info['email']
        phone = self.license_manager.hidden_info['phone']
        company = self.license_manager.hidden_info['company']
        address = self.license_manager.hidden_info['reference_address']
        serial_number = self.license_manager.hidden_info['serial_number']
        license_key = self.license_key_input.text()
        plan = self.plan_combo.currentText()
        duration = self.duration_combo.currentText()
        current_license_revision = self.license_manager.hidden_info['license_revision']

        if plan == "Professional":
            if duration == "1 year":
                duration = 1
            elif duration == "3 years":
                duration = 3
            elif duration == "5 years":
                duration = 5
        elif plan == "Enterprise":
            if duration == "1 year":
                duration = 1
            elif duration == "3 years":
                duration = 3
            elif duration == "5 years":
                duration = 5

        activation_result = self.license_manager.activate_license(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            company=company,
            reference_address=address,
            serial_number=serial_number,
            license_key=license_key,
            subscription_plan=plan,
            duration_years=duration,
            license_revision=current_license_revision,
        )
        self.lic_change = False
        if activation_result == "Already used":
            QMessageBox.critical(self, "Error Activating License", "The license key has already been used or has expired. Please contact RedBee support for assistance.")
        elif activation_result == "Invalid":
            QMessageBox.critical(self, "Error Activating License", "The license key is invalid. Please check the key and try again, or contact RedBee support for assistance.")
        elif activation_result == "Failed to delete old license":
            QMessageBox.critical(self, "Error Activating License", "Failed to renew license. Please contact RedBee support for assistance.")
            self.close()
        elif activation_result == "License changed":
            QMessageBox.information(self, "License modified", "License activated successfully.")
            self.close()
        elif activation_result == "License activated":
            QMessageBox.information(self, "License activated", "License activated successfully.")
            self.close()


# ---------------------Widgets---------------------#
# Main tab widget for the user interface
class MainWidget(QWidget):
    def __init__(self, core):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainWidget: initializing.."
        )
        super().__init__()
        self.core = core
        self.current_user = None
        self.current_role = None
        if self.core.auth_handler.active_user:
            self.current_user = self.core.auth_handler.active_user
            self.current_role = self.core.auth_handler.get_user_role()

        self.initUI()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MainWidget: Initialized!"
        )

    def initUI(self):
        self.setWindowTitle(MAIN_WIDGET_TITLE)

        # Load image
        pixmap = QPixmap(ICON_FULL_LOGO)
        self.logo_label = QLabel()
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)

        self.license_status_label = QLabel(
            f"License Status: {self.core.info_manager.license_manager.activation_status}"
        )
        self.license_status_label.setStyleSheet(MAIN_WIDGET_TEXT_COLOR)
        self.license_status_label.setAlignment(Qt.AlignCenter)

        # Connect and Disconnect buttons
        self.connect_button = QPushButton("Connect")
        self.disconnect_button = QPushButton("Disconnect")
        self.connect_button.clicked.connect(lambda: self.update_indicator("yellow"))
        self.connect_button.clicked.connect(self.core.connect_opcua)
        self.disconnect_button.clicked.connect(lambda: self.update_indicator("yellow"))
        self.disconnect_button.clicked.connect(self.core.disconnect_opcua)
        button_palette = self.connect_button.palette()
        button_palette.setColor(QPalette.ButtonText, Qt.black)
        self.connect_button.setPalette(button_palette)
        button_palette = self.disconnect_button.palette()
        button_palette.setColor(QPalette.ButtonText, Qt.black)
        self.disconnect_button.setPalette(button_palette)

        # Status label indicator
        self.status_label = QLabel("Status: ")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet(MAIN_WIDGET_TEXT_COLOR)

        # Indicator for connection status definition and set to red
        self.indicator_label = RoundIndicator()
        self.update_indicator("red")

        # Certificate Handler button
        self.cert_handler_button = QPushButton()
        self.cert_handler_button.setIcon(QIcon(ICON_CERTIFICATE))
        self.cert_handler_button.setToolTip("Certificate Handler")
        self.cert_handler_button.setStyleSheet("color: black;")
        self.cert_handler_button.clicked.connect(self.open_cert_handler_window)

        # Historian button
        self.historian_button = QPushButton()
        self.historian_button.setIcon(QIcon(ICON_HISTORIAN))
        self.historian_button.setToolTip("Alarm Historian")
        self.historian_button.setStyleSheet("color: black;")
        self.historian_button.clicked.connect(self.open_historian_window)

        # User button
        self.user_button = QPushButton()
        self.user_button.setIcon(QIcon(ICON_USER))
        self.user_button.setToolTip("User Management")
        self.user_button.setStyleSheet("color: black;")
        self.user_button.clicked.connect(self.open_user_window)

        # Settings button
        self.settings_button = QToolButton()
        self.settings_button.setIcon(QIcon(ICON_GEAR))
        self.settings_button.setToolTip("Settings")
        self.settings_button.setStyleSheet("color: black;")
        self.settings_button.clicked.connect(self.open_settings_window)

        # Status layout with settings button aligned to the right
        status_layout = QHBoxLayout()
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.indicator_label)
        status_layout.addStretch()
        if self.current_role:
            if (
                "View certificate window"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Certificate"]
            ):
                status_layout.addWidget(self.cert_handler_button)
            if (
                "View alarm log window"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Alarm Log"]
            ):
                status_layout.addWidget(self.historian_button)
            if (
                "View user window"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["User_manager"]
            ):
                status_layout.addWidget(self.user_button)
            if (
                self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Settings"]
                != []
            ):
                status_layout.addWidget(self.settings_button)
        else:
            status_layout.addWidget(self.cert_handler_button)
            status_layout.addWidget(self.historian_button)
            status_layout.addWidget(self.user_button)
            status_layout.addWidget(self.settings_button)

        # Make buttons taller
        self.connect_button.setFixedHeight(50)
        self.disconnect_button.setFixedHeight(50)
        # Set button colors
        self.connect_button.setStyleSheet(MAIN_WIDGET_BUTTON_CONNECT_COLOR)
        self.disconnect_button.setStyleSheet(MAIN_WIDGET_BUTTON_DISCONNECT_COLOR)
        # Connect buttons to their functions
        self.connect_button.clicked.connect(self.on_connect_clicked)
        self.disconnect_button.clicked.connect(self.on_disconnect_clicked)
        # Layout for buttons
        button_layout = QHBoxLayout()
        if self.current_role:
            if (
                "Start"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Main"]
            ):
                button_layout.addWidget(self.connect_button)
            if (
                "Stop"
                in self.core.info_manager.setting_manager.auth_handler.roles[
                    self.current_role
                ]["Main"]
            ):
                button_layout.addWidget(self.disconnect_button)
        else:
            button_layout.addWidget(self.connect_button)
            button_layout.addWidget(self.disconnect_button)
        # Main layout
        layout = QVBoxLayout()
        layout.addWidget(self.logo_label)
        layout.addStretch()
        layout.addWidget(self.license_status_label)
        layout.addStretch()

        layout.addLayout(button_layout)
        layout.addLayout(status_layout)
        # Center buttons vertically
        layout.setContentsMargins(0, 0, 0, 0)  # Set all margins to 0
        layout.setAlignment(Qt.AlignTop)

        self.setLayout(layout)

    def on_connect_clicked(self):
        if self.core.opcua_client:
            self.connect_button.setEnabled(False)

    def on_disconnect_clicked(self):
        self.connect_button.setEnabled(True)

    def update_indicator(self, color):
        if color == "red":
            self.indicator_label.color = Qt.red
        elif color == "yellow":
            self.indicator_label.color = Qt.yellow
        elif color == "green":
            self.indicator_label.color = Qt.green
        self.indicator_label.update()

    def open_settings_window(self):
        try:
            settings_window = SettingsWindow(self.core.setting_manager)
            settings_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "SettingsWindow", "Error", QMessageBox.Critical
            )

    def open_historian_window(self):
        try:
            historian_window = HistorianWindow(self.core.auth_handler)
            historian_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "HistorianWindow", "Error", QMessageBox.Critical
            )

    def open_cert_handler_window(self):
        try:
            self.cert_handler_window = CertHandlerWindow(self.core)
            self.cert_handler_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "CertHandlerWindow", "Error", QMessageBox.Critical
            )

    def open_user_window(self):
        try:
            user_window = UserWindow(self.core.auth_handler)
            user_window.exec()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "UserWindow", "Error", QMessageBox.Critical
            )


# General setting widget for the user interface
class GeneralSettingsWidget(QWidget):
    def __init__(self, setting_manager):
        super().__init__()
        self.setting_manager = setting_manager
        self.initUI()

    def initUI(self):
        # Create layout
        grid_layout = QGridLayout()
        
        # Checkbox for Authentication
        self.auth_checkbox = QCheckBox("Require Authentication")
        self.auth_checkbox.setChecked(
            self.setting_manager.general_settings["authentication"]
        )
        self.auth_checkbox.clicked.connect(self.toggle_auth)
        grid_layout.addWidget(self.auth_checkbox, 0, 0, 1, 2)
        
        # Checkbox for Lock Timer
        self.lock_timer_checkbox = QCheckBox("Lock Timer")
        self.lock_timer_checkbox.setChecked(
            self.setting_manager.general_settings["lock_timer"]
        )
        self.lock_timer_checkbox.setEnabled(
            self.setting_manager.general_settings["authentication"]
        )
        self.lock_timer_checkbox.stateChanged.connect(self.toggle_lock_timer)
        grid_layout.addWidget(self.lock_timer_checkbox, 1, 0)

        # Lock Timer ComboBox
        self.lock_timer_combobox = QComboBox()
        self.lock_timer_combobox.addItems(
            ["30 minutes", "1 hour", "2 hours", "4 hours", "8 hours"]
        )
        self.lock_timer_combobox.setCurrentText(
            self.setting_manager.general_settings["lock_timer_value"]
        )
        self.lock_timer_combobox.setEnabled(
            self.setting_manager.general_settings["lock_timer"]
        )
        self.lock_timer_combobox.currentTextChanged.connect(self.change_lock_timer)
        grid_layout.addWidget(self.lock_timer_combobox, 1, 1)
        
        # Checkbox for Auto Connect
        self.auto_connect_checkbox = QCheckBox("Connect at start-up")
        self.auto_connect_checkbox.setChecked(
            self.setting_manager.general_settings["auto_connect"]
        )
        self.auto_connect_checkbox.stateChanged.connect(self.toggle_auto_connect)
        grid_layout.addWidget(self.auto_connect_checkbox, 2, 0, 1, 2)
        
        # Checkbox for Dark Theme
        self.dark_theme_checkbox = QCheckBox("Dark Mode")
        self.dark_theme_checkbox.setChecked(
            self.setting_manager.general_settings["dark_theme"]
        )
        self.dark_theme_checkbox.stateChanged.connect(self.toggle_dark_theme)
        grid_layout.addWidget(self.dark_theme_checkbox, 3, 0, 1, 2)
        
        # Drop-down menu for Language Selection
        language_label = QLabel("Language:")
        self.language_combobox = QComboBox()
        self.language_combobox.addItems(
            ["English", "Italian", "Spanish", "French", "German"]
        )
        self.language_combobox.setCurrentText(
            self.setting_manager.general_settings["language"]
        )
        self.language_combobox.currentTextChanged.connect(self.change_language)
        #grid_layout.addWidget(language_label, 4, 0)
        #grid_layout.addWidget(self.language_combobox, 4, 1)

        # Adjust row and column stretching for minimal vertical distance
        grid_layout.setRowStretch(10, 1)
        grid_layout.setColumnStretch(1, 0)

        # User Label
        if self.setting_manager.auth_handler.active_user:
            self.user_layout = QHBoxLayout()
            self.user_label = QLabel(
                f"User: {self.setting_manager.auth_handler.active_user} | {self.setting_manager.auth_handler.login_time.strftime('%d-%m-%Y | %H:%M:%S')}"
            )
            self.user_layout.addWidget(self.user_label)
            self.user_layout.addStretch()

            

        
        # Set the layout for the widget
        layout = QVBoxLayout()
        layout.addLayout(grid_layout)
        if self.setting_manager.auth_handler.active_user:
            layout.addLayout(self.user_layout)

        self.setLayout(layout)

    def toggle_auth(self):
        auth = self.setting_manager.auth_handler.authentication()
        if not auth:
            self.auth_checkbox.setChecked(not self.auth_checkbox.isChecked())
        else:
            self.setting_manager.general_settings["authentication"] = (
                self.auth_checkbox.isChecked()
            )
        if not self.auth_checkbox.isChecked():
            self.lock_timer_checkbox.setChecked(False)
            self.lock_timer_checkbox.setEnabled(False)
            self.setting_manager.general_settings["lock_timer"] = False
        else:
            self.lock_timer_checkbox.setEnabled(True)
            self.setting_manager.general_settings["lock_timer"] = True
        self.setting_manager.save_config()

    def toggle_lock_timer(self, checked):
        self.setting_manager.general_settings["lock_timer"] = checked
        if not self.lock_timer_combobox.isEnabled():
            self.setting_manager.general_settings["lock_timer_value"] = "30 minutes"
            self.lock_timer_combobox.setCurrentText("30 minutes")
            self.setting_manager.auth_handler.auto_logout_worker.stop()
        else:
            self.setting_manager.general_settings["lock_timer_value"] = (
                self.lock_timer_combobox.currentText()
            )
            self.setting_manager.auth_handler.auto_logout_worker.start()
        self.setting_manager.save_config()
        self.lock_timer_combobox.setEnabled(checked)

    def change_lock_timer(self):
        self.setting_manager.general_settings["lock_timer_value"] = (
            self.lock_timer_combobox.currentText()
        )
        self.setting_manager.save_config()

    def toggle_auto_connect(self, checked):
        self.setting_manager.general_settings["auto_connect"] = checked
        self.setting_manager.save_config()

    def toggle_dark_theme(self, checked):
        if checked:
            QApplication.instance().setStyle("Fusion")
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.Base, QColor(42, 42, 42))
            dark_palette.setColor(QPalette.AlternateBase, QColor(66, 66, 66))
            dark_palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
            QApplication.instance().setPalette(dark_palette)
        else:
            QApplication.instance().setStyle("Fusion")
            light_palette = QPalette()
            light_palette.setColor(QPalette.Window, QColor(240, 240, 240))
            light_palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
            light_palette.setColor(QPalette.Base, QColor(255, 255, 255))
            light_palette.setColor(QPalette.AlternateBase, QColor(233, 231, 227))
            light_palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
            light_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
            light_palette.setColor(QPalette.Text, QColor(0, 0, 0))
            light_palette.setColor(QPalette.Button, QColor(240, 240, 240))
            light_palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
            light_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            light_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            light_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            light_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            QApplication.instance().setPalette(light_palette)

        self.setting_manager.general_settings["dark_theme"] = checked
        self.setting_manager.save_config()

    def change_language(self):
        self.setting_manager.general_settings["language"] = (
            self.language_combobox.currentText()
        )
        self.setting_manager.save_config()


# OPC Settings widget for the user interface
class OPCSettingsWidget(QWidget):
    def __init__(self, setting_manager):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OPCSettingsWidget: initializing.."
        )
        super().__init__()
        self.setting_manager = setting_manager
        self.initUI()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OPCSettingsWidget: Initialized!"
        )

    def initUI(self):
        # Create widgets
        self.host_label = QLabel("OPC Server Host:")
        self.host_input = QLineEdit(self.setting_manager.opc_settings["host"])
        self.port_label = QLabel("OPC Server Port:")
        self.port_input = QLineEdit(self.setting_manager.opc_settings["port"])
        self.security_mode_label = QLabel("Security Mode:")
        self.security_mode_input = QComboBox()
        self.security_mode_input.addItems(["None", "Sign", "SignAndEncrypt"])
        self.security_mode_input.setCurrentText(
            self.setting_manager.opc_settings["security_mode"]
        )
        self.security_policy_label = QLabel("Security Policy:")
        self.security_policy_input = QComboBox()
        self.security_policy_input.addItems(
            ["None", "Basic128Rsa15", "Basic256", "Basic256Sha256"]
        )
        self.security_policy_input.setCurrentText(
            self.setting_manager.opc_settings["security_policy"]
        )
        self.anonymous_checkbox = QCheckBox("Anonymous access")
        self.anonymous_checkbox.setChecked(
            self.setting_manager.opc_settings["anonymous"]
        )
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit(self.setting_manager.opc_settings["username"])
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit(self.setting_manager.opc_settings["password"])
        self.password_input.setEchoMode(QLineEdit.Password)
        self.save_button = QPushButton("Save")
        self.test_button = QPushButton("Test")

        # Set initial states and connections
        self.username_input.setEnabled(self.anonymous_checkbox.isChecked())
        self.password_input.setEnabled(self.anonymous_checkbox.isChecked())
        self.save_button.setEnabled(False)
        self.test_button.setEnabled(True)

        self.host_input.textChanged.connect(self.setting_check)
        self.port_input.textChanged.connect(self.setting_check)
        self.security_mode_input.currentTextChanged.connect(self.setting_check)
        self.security_policy_input.currentTextChanged.connect(self.setting_check)
        self.anonymous_checkbox.stateChanged.connect(self.setting_check)
        self.anonymous_checkbox.stateChanged.connect(self.toggle_username_password)
        self.save_button.clicked.connect(self.save_config)
        self.test_button.clicked.connect(self.test_config)

        # Create grid layout
        grid_layout = QGridLayout()
        # grid_layout.setSpacing(10)  # Reduce vertical spacing

        # Add widgets to the grid layout
        grid_layout.addWidget(self.host_label, 0, 0)
        grid_layout.addWidget(self.host_input, 0, 1)
        grid_layout.addWidget(self.port_label, 1, 0)
        grid_layout.addWidget(self.port_input, 1, 1)
        grid_layout.addWidget(self.security_mode_label, 2, 0)
        grid_layout.addWidget(self.security_mode_input, 2, 1)
        grid_layout.addWidget(self.security_policy_label, 3, 0)
        grid_layout.addWidget(self.security_policy_input, 3, 1)
        grid_layout.addWidget(self.anonymous_checkbox, 4, 0, 1, 2)  # Span across columns
        grid_layout.addWidget(self.username_label, 5, 0)
        grid_layout.addWidget(self.username_input, 5, 1)
        grid_layout.addWidget(self.password_label, 6, 0)
        grid_layout.addWidget(self.password_input, 6, 1)
        grid_layout.setRowStretch(10, 1)
        grid_layout.setColumnStretch(1, 1)

        # Add buttons at the bottom
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.save_button)
        button_layout.setAlignment(Qt.AlignRight)

        # Set layout
        main_layout = QVBoxLayout()
        main_layout.addLayout(grid_layout)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

        # Set the main layout for the widget
        self.setLayout(main_layout)

        # Connect signals
        self.security_mode_input.currentTextChanged.connect(
            self.handle_security_mode_change
        )
        self.handle_security_mode_change(self.security_mode_input.currentText())

    def handle_security_mode_change(self, text):
        if text == "None":
            self.anonymous_checkbox.setChecked(True)
            self.security_policy_input.setCurrentText("None")
            self.security_policy_input.setEnabled(False)
            self.username_input.setEnabled(False)
            self.password_input.setEnabled(False)
        else:
            self.security_policy_input.setEnabled(True)

    def toggle_username_password(self):
        if self.anonymous_checkbox.isChecked():
            self.username_input.setText("")
            self.password_input.setText("")
            self.username_input.setEnabled(False)
            self.password_input.setEnabled(False)
            self.username_input.setStyleSheet("")
            self.password_input.setStyleSheet("")
        else:
            self.username_input.setEnabled(True)
            self.password_input.setEnabled(True)
            self.username_input.setStyleSheet("")
            self.password_input.setStyleSheet("")

    def save_config(self):
        config = {
            "host": self.host_input.text(),
            "port": self.port_input.text(),
            "security_mode": self.security_mode_input.currentText(),
            "security_policy": self.security_policy_input.currentText(),
            "anonymous": self.anonymous_checkbox.isChecked(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
        }
        self.setting_manager.opc_settings = config
        self.setting_manager.save_config()
        QMessageBox.information(self, "Success", "OPC configuration saved successfully")
        self.save_button.setEnabled(False)

    def is_valid_host(self, host):
        ip_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        hostname_pattern = r"^(?=.{1,255}$)[0-9A-Za-z](?:[0-9A-Za-z-]{0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]{0,61}[0-9A-Za-z])?)*$"
        if re.match(ip_pattern, host):
            return True
        elif re.match(hostname_pattern, host):
            return True
        else:
            return False

    def is_valid_port(self, port):
        try:
            port_num = int(port)
            if 0 < port_num <= 65535:
                return True
            else:
                return False
        except ValueError:
            return False

    def setting_check(self):
        host_valid = self.is_valid_host(self.host_input.text())
        port_valid = self.is_valid_port(self.port_input.text())
        user_valid = bool(self.username_input.text().strip())
        if host_valid:
            if port_valid:
                if self.security_mode_input.currentText() != "None":
                    if self.security_policy_input.currentText() != "None":
                        if not self.anonymous_checkbox.isChecked():
                            if len(self.username_input.text()) > 0:
                                self.save_button.setEnabled(True)
                                self.test_button.setEnabled(True)
                            else:
                                self.save_button.setEnabled(False)
                                self.test_button.setEnabled(False)
                        else:
                            self.save_button.setEnabled(True)
                            self.test_button.setEnabled(True)
                    else:
                        self.save_button.setEnabled(False)
                        self.test_button.setEnabled(False)
                else:
                    if not self.anonymous_checkbox.isChecked():
                        if len(self.username_input.text()) > 0:
                            self.save_button.setEnabled(True)
                            self.test_button.setEnabled(True)
                        else:
                            self.save_button.setEnabled(False)
                            self.test_button.setEnabled(False)
                    else:
                        self.save_button.setEnabled(True)
                        self.test_button.setEnabled(True)
            else:
                self.save_button.setEnabled(False)
                self.test_button.setEnabled(False)
        else:
            self.save_button.setEnabled(False)
            self.test_button.setEnabled(False)

        if not host_valid:
            self.host_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
        else:
            self.host_input.setStyleSheet("")
        if not port_valid:
            self.port_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
        else:
            self.port_input.setStyleSheet("")
        if self.anonymous_checkbox.isChecked():
            self.username_input.setStyleSheet("")
        else:
            if user_valid:
                self.username_input.setStyleSheet("")
            else:
                self.username_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)

    def test_config(self):
        class CertTest:
            def __init__(self):
                self.cert_path = OWN_CERTIFICATE_FILE_PATH
                self.private_key_path = OWN_PRIVATE_KEY_FILE_PATH

        certificate = CertTest()
        client = OpcUaClient(
            self.host_input.text(),
            self.port_input.text(),
            self.security_mode_input.currentText(),
            self.security_policy_input.currentText(),
            self.username_input.text(),
            self.password_input.text(),
            certificate,
        )
        try:
            client.connect()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "TestOPC", "Error", QMessageBox.Critical
            )
        else:
            try:
                client.disconnect()
            except Exception as e:
                ExceptionHandler.handle_exception(
                    str(e), "TestOPC", "Error", QMessageBox.Critical
                )
            else:
                QMessageBox.information(self, "TestOPC", "Connection successful")
        finally:
            client = None
            certificate = None


# Alarm Subscription widget for the user interface
class AlarmSubscriptionWidget(QWidget):
    def __init__(self, setting_manager):
        super().__init__()
        self.setting_manager = setting_manager
        self.initUI()

    def initUI(self):
        # Create widgets
        self.lower_threshold_label = QLabel("Notification Threshold Lower Limit:")
        self.lower_threshold_input = QLineEdit(
            self.setting_manager.alarm_subscription["notification_threshold_lower"]
        )
        self.lower_threshold_input.textChanged.connect(self.check_thresholds)
        
        self.upper_threshold_label = QLabel("Notification Threshold Upper Limit:")
        self.upper_threshold_input = QLineEdit(
            self.setting_manager.alarm_subscription["notification_threshold_upper"]
        )
        self.upper_threshold_input.textChanged.connect(self.check_thresholds)
        
        self.error_label = QLabel("")
        self.error_label.setStyleSheet(ERROR_TEXT_COLOR)
        
        self.save_button = QPushButton("Save")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_config)
        
        # Create a grid layout
        grid_layout = QGridLayout()
        
        # Add widgets to the grid layout
        grid_layout.addWidget(self.lower_threshold_label, 0, 0)
        grid_layout.addWidget(self.lower_threshold_input, 0, 1)
        grid_layout.addWidget(self.upper_threshold_label, 1, 0)
        grid_layout.addWidget(self.upper_threshold_input, 1, 1)
        grid_layout.addWidget(self.error_label, 2, 0, 1, 2)  # Span across 2 columns
        grid_layout.setRowStretch(10, 1)
        grid_layout.setColumnStretch(1, 1)        
        
        # Create button layout and add it to the grid layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.save_button)
        button_layout.setAlignment(Qt.AlignRight)
        # Set the grid layout to the widget
        main_layout = QVBoxLayout()
        main_layout.addLayout(grid_layout)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)






    def check_thresholds(self):
        try:
            lower_limit = int(self.lower_threshold_input.text())
        except ValueError:
            self.error_label.setText("Error: Invalid input")
            self.lower_threshold_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            self.save_button.setEnabled(False)
            return

        try:
            upper_limit = int(self.upper_threshold_input.text())
        except ValueError:
            self.error_label.setText("Error: Invalid input")
            self.upper_threshold_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            self.save_button.setEnabled(False)
            return

        if (
            lower_limit < 0
            or lower_limit > 1000
            or upper_limit < 0
            or upper_limit > 1000
        ):
            self.error_label.setText("Error: Limits have to be in the range [0-1000]")
            if lower_limit < 0 or lower_limit > 1000:
                self.lower_threshold_input.setStyleSheet(
                    INPUT_FORM_ERROR_BACKGROUND_COLOR
                )
            else:
                self.lower_threshold_input.setStyleSheet("")
            if upper_limit < 0 or upper_limit > 1000:
                self.upper_threshold_input.setStyleSheet(
                    INPUT_FORM_ERROR_BACKGROUND_COLOR
                )
            else:
                self.upper_threshold_input.setStyleSheet("")
            self.save_button.setEnabled(False)
        elif upper_limit <= lower_limit:
            self.error_label.setText(
                "Error: Upper limit has to be greater than lower limit"
            )
            self.lower_threshold_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            self.upper_threshold_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            self.save_button.setEnabled(False)
        else:
            self.error_label.setText("")
            self.lower_threshold_input.setStyleSheet("")
            self.upper_threshold_input.setStyleSheet("")
            self.save_button.setEnabled(True)

    def save_config(self):
        config = {
            "notification_threshold_lower": self.lower_threshold_input.text(),
            "notification_threshold_upper": self.upper_threshold_input.text(),
        }
        self.setting_manager.alarm_subscription = config
        self.setting_manager.save_config()
        QMessageBox.information(
            self, "Success", "Alarm configuration saved successfully"
        )
        self.save_button.setEnabled(False)


# Twilio Settings widget for the user interface
class TwilioSettingsWidget(QWidget):
    def __init__(self, setting_manager):
        super().__init__()
        self.setting_manager = setting_manager
        self.initUI()

    def initUI(self):
        # Initialize Widgets
        self.twilio_enabled = QCheckBox("Twilio notification enabled")
        self.twilio_enabled.setChecked(
            self.setting_manager.twilio_settings["twilio_enabled"]
        )
        self.twilio_enabled.clicked.connect(self.toggle_settings)
        self.twilio_enabled.clicked.connect(self.setting_check)

        self.twilio_sid_label = QLabel("Twilio SID:")
        self.twilio_sid_input = QLineEdit(
            self.setting_manager.twilio_settings["twilio_sid"]
        )
        self.twilio_sid_input.textChanged.connect(self.setting_check)

        self.twilio_token_label = QLabel("Twilio Auth Token:")
        self.twilio_token_input = QLineEdit(
            self.setting_manager.twilio_settings["twilio_auth_token"]
        )
        self.twilio_token_input.setEchoMode(QLineEdit.Password)
        self.twilio_token_input.textChanged.connect(self.setting_check)

        self.twilio_number_label = QLabel("Twilio Number:")
        self.twilio_number_input = QLineEdit(
            self.setting_manager.twilio_settings["twilio_number"]
        )
        self.twilio_number_input.textChanged.connect(self.setting_check)
        self.error_twilio_number_input = QLabel()
        self.error_twilio_number_input.setStyleSheet(ERROR_TEXT_COLOR)

        self.receiver_number_label = QLabel("Receiver Number:")
        self.receiver_number_input = QLineEdit(
            self.setting_manager.twilio_settings["receiver_number"]
        )
        self.receiver_number_input.textChanged.connect(self.setting_check)
        self.error_receiver_number_input = QLabel()
        self.error_receiver_number_input.setStyleSheet(ERROR_TEXT_COLOR)

        self.test_button = QPushButton("Test")
        self.test_button.clicked.connect(self.test_config)
        self.test_button.setEnabled(True)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_config)
        self.save_button.setEnabled(False)

        # Create Layouts
        grid_layout = QGridLayout()

        # Add Widgets to GridLayout
        grid_layout.addWidget(self.twilio_sid_label, 0, 0)
        grid_layout.addWidget(self.twilio_sid_input, 0, 1)
        grid_layout.addWidget(self.twilio_token_label, 1, 0)
        grid_layout.addWidget(self.twilio_token_input, 1, 1)
        grid_layout.addWidget(self.twilio_number_label, 2, 0)
        grid_layout.addWidget(self.twilio_number_input, 2, 1)
        grid_layout.addWidget(self.error_twilio_number_input, 2, 2)
        grid_layout.addWidget(self.receiver_number_label, 3, 0)
        grid_layout.addWidget(self.receiver_number_input, 3, 1)
        grid_layout.addWidget(self.error_receiver_number_input, 3, 2)
        grid_layout.setRowStretch(10, 1)
        grid_layout.setColumnStretch(1, 1)

        # Add the checkbox and buttons
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.twilio_enabled)
        main_layout.addLayout(grid_layout)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.save_button)
        button_layout.setAlignment(Qt.AlignRight)
        
        main_layout.addLayout(button_layout)

        # Set the main layout for the widget
        self.setLayout(main_layout)

        # Initial setup
        self.toggle_settings()
        # self.setting_check()

    def toggle_settings(self):
        enabled = self.twilio_enabled.isChecked()
        for widget in [
            self.twilio_sid_label,
            self.twilio_sid_input,
            self.twilio_token_label,
            self.twilio_token_input,
            self.twilio_number_label,
            self.twilio_number_input,
            self.receiver_number_label,
            self.receiver_number_input,
        ]:
            widget.setEnabled(enabled)
            if not enabled:
                widget.setStyleSheet("")

    def save_config(self):
        config = {
            "twilio_enabled": self.twilio_enabled.isChecked(),
            "twilio_sid": self.twilio_sid_input.text(),
            "twilio_auth_token": self.twilio_token_input.text(),
            "twilio_number": self.twilio_number_input.text(),
            "receiver_number": self.receiver_number_input.text(),
        }
        self.setting_manager.twilio_settings = config
        self.setting_manager.save_config()
        QMessageBox.information(
            self, "Success", "Twilio configuration saved successfully"
        )
        self.save_button.setEnabled(False)

    def setting_check(self):
        number_pattern = r"^\+[1-9]\d{4,14}$"
        twilio_param_pattern = r"^[a-zA-Z0-9]{30,37}$"
        twilio_number_valid = bool(
            re.match(number_pattern, self.twilio_number_input.text())
        )
        receiver_number_valid = bool(
            re.match(number_pattern, self.receiver_number_input.text())
        )
        twilio_sid_valid = bool(
            re.match(twilio_param_pattern, self.twilio_sid_input.text())
        )
        twilio_token_valid = bool(
            re.match(twilio_param_pattern, self.twilio_token_input.text())
        )
        if self.twilio_enabled.isChecked():
            if not twilio_number_valid:
                self.twilio_number_input.setStyleSheet(
                    INPUT_FORM_ERROR_BACKGROUND_COLOR
                )
                self.error_twilio_number_input.setText(
                    'Error: Invalid number format. Use "+1234567890"'
                )
            else:
                self.twilio_number_input.setStyleSheet("")
                self.error_twilio_number_input.setText("")
            if not receiver_number_valid:
                self.receiver_number_input.setStyleSheet(
                    INPUT_FORM_ERROR_BACKGROUND_COLOR
                )
                self.error_receiver_number_input.setText(
                    'Error: Invalid number format. Use "+1234567890"'
                )
            else:
                self.receiver_number_input.setStyleSheet("")
                self.error_receiver_number_input.setText("")
            if not twilio_sid_valid:
                self.twilio_sid_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.twilio_sid_input.setStyleSheet("")
            if not twilio_token_valid:
                self.twilio_token_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.twilio_token_input.setStyleSheet("")
            if (
                twilio_number_valid
                and receiver_number_valid
                and twilio_sid_valid
                and twilio_token_valid
            ):
                self.save_button.setEnabled(True)
                self.test_button.setEnabled(True)
            else:
                self.save_button.setEnabled(False)
                self.test_button.setEnabled(False)
        else:
            if (
                twilio_number_valid
                and receiver_number_valid
                and twilio_sid_valid
                and twilio_token_valid
            ):
                self.save_button.setEnabled(True)
                self.test_button.setEnabled(True)
            else:
                self.save_button.setEnabled(False)
                self.test_button.setEnabled(False)

    def test_config(self):
        test_sms = SmsSender(
            self.twilio_sid_input.text(),
            self.twilio_token_input.text(),
            self.twilio_number_input.text(),
            self.receiver_number_input.text(),
        )
        try:
            if (
                not self.twilio_sid_input.text()
                or not self.twilio_token_input.text()
                or not self.twilio_number_input.text()
                or not self.receiver_number_input.text()
            ):
                raise Exception("All parameter are needed!")
            else:
                test_sms.send_sms("Test message from RedBee OPC Event Notifier")
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "TestTwilio", "Error", QMessageBox.Critical
            )
        else:
            QMessageBox.information(self, "Success", "Test SMS sent successfully")
        finally:
            test_sms = None


# SMTP Settings widget for the user interface
class SMTPSettingsWidget(QWidget):
    def __init__(self, setting_manager):
        super().__init__()
        self.setting_manager = setting_manager
        self.initUI()

    def initUI(self):
        # Initialize widgets
        self.mail_enabled = QCheckBox("Mail notification enabled")
        self.mail_enabled.setChecked(self.setting_manager.smtp_settings["mail_enabled"])
        self.mail_enabled.clicked.connect(self.toggle_settings)
        self.mail_enabled.clicked.connect(self.setting_check)

        self.mail_server_label = QLabel("Mail Server Address:")
        self.mail_server_input = QLineEdit(self.setting_manager.smtp_settings["mail_server_address"])
        self.mail_server_input.textChanged.connect(self.setting_check)
        self.error_mail_server_input = QLabel()
        self.error_mail_server_input.setStyleSheet("color: red;")

        self.mail_port_label = QLabel("Mail Server Port:")
        self.mail_port_input = QLineEdit(self.setting_manager.smtp_settings["port_mail"])
        self.mail_port_input.textChanged.connect(self.setting_check)
        self.error_mail_port_input = QLabel()
        self.error_mail_port_input.setStyleSheet("color: red;")

        self.ssl_checkbox = QCheckBox("Enable SSL/TLS")
        self.ssl_checkbox.setChecked(self.setting_manager.smtp_settings["ssl_enabled"])

        self.sender_mail_label = QLabel("Sender Email:")
        self.sender_mail_input = QLineEdit(self.setting_manager.smtp_settings["sender_mail"])
        self.sender_mail_input.textChanged.connect(self.setting_check)
        self.error_sender_mail_input = QLabel()
        self.error_sender_mail_input.setStyleSheet("color: red;")

        self.sender_password_label = QLabel("Sender Password:")
        self.sender_password_input = QLineEdit(self.setting_manager.smtp_settings["sender_password"])
        self.sender_password_input.setEchoMode(QLineEdit.Password)
        self.sender_password_input.textChanged.connect(self.setting_check)

        self.receiver_mail_label = QLabel("Receiver Email:")
        self.receiver_mail_input = QLineEdit(self.setting_manager.smtp_settings["receiver_mail"])
        self.receiver_mail_input.textChanged.connect(self.setting_check)
        self.error_receiver_mail_input = QLabel()
        self.error_receiver_mail_input.setStyleSheet("color: red;")

        self.test_button = QPushButton("Test")
        self.test_button.clicked.connect(self.test_config)
        self.test_button.setEnabled(bool(self.sender_password_input.text()))

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_config)
        self.save_button.setEnabled(False)

        # Create and set the grid layout
        grid = QGridLayout()

        # Add widgets to the grid
        grid.addWidget(self.mail_enabled, 0, 0, 1, 2)
        
        grid.addWidget(self.mail_server_label, 1, 0)
        grid.addWidget(self.mail_server_input, 1, 1)
        grid.addWidget(self.error_mail_server_input, 1, 2)

        grid.addWidget(self.mail_port_label, 2, 0)
        grid.addWidget(self.mail_port_input, 2, 1)
        grid.addWidget(self.error_mail_port_input, 2, 2)

        grid.addWidget(self.ssl_checkbox, 3, 0, 1, 2)

        grid.addWidget(self.sender_mail_label, 4, 0)
        grid.addWidget(self.sender_mail_input, 4, 1)
        grid.addWidget(self.error_sender_mail_input, 4, 2)

        grid.addWidget(self.sender_password_label, 5, 0)
        grid.addWidget(self.sender_password_input, 5, 1)

        grid.addWidget(self.receiver_mail_label, 6, 0)
        grid.addWidget(self.receiver_mail_input, 6, 1)
        grid.addWidget(self.error_receiver_mail_input, 6, 2)
        grid.setRowStretch(10, 1)
        grid.setColumnStretch(1, 1)

        # Create a horizontal layout for buttons
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.save_button)
        button_layout.setAlignment(Qt.AlignRight)

        # Main layout
        layout = QVBoxLayout()
        layout.addLayout(grid)
        layout.addSpacing(10)
        layout.addLayout(button_layout)
        layout.setAlignment(Qt.AlignTop)

        self.setLayout(layout)
        self.toggle_settings()

    def toggle_settings(self):
        enabled = self.mail_enabled.isChecked()
        for widget in [
            self.mail_server_label,
            self.mail_server_input,
            self.mail_port_label,
            self.mail_port_input,
            self.ssl_checkbox,
            self.sender_mail_label,
            self.sender_mail_input,
            self.sender_password_label,
            self.sender_password_input,
            self.receiver_mail_label,
            self.receiver_mail_input,
        ]:
            widget.setEnabled(enabled)

    def setting_check(self):
        sender_email = self.sender_mail_input.text()
        receiver_email = self.receiver_mail_input.text()
        mail_server = self.mail_server_input.text()
        mail_port = self.mail_port_input.text()
        sender_password = self.sender_password_input.text()

        sender_valid = self.is_valid_email(sender_email)
        receiver_valid = self.is_valid_email(receiver_email)
        server_valid = self.is_valid_host(mail_server)
        server_port_valid = self.is_valid_port(mail_port)
        password_valid = bool(sender_password.strip())
        if self.mail_enabled.isChecked():
            if not sender_valid:
                self.sender_mail_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
                self.error_sender_mail_inut.setText("Error: Invalid email")
            else:
                self.sender_mail_input.setStyleSheet("")
                self.error_sender_mail_inut.setText("")
            if not receiver_valid:
                self.receiver_mail_input.setStyleSheet(
                    INPUT_FORM_ERROR_BACKGROUND_COLOR
                )
                self.error_receiver_mail_input.setText("Error: Invalid email")
            else:
                self.receiver_mail_input.setStyleSheet("")
                self.error_receiver_mail_input.setText("")
            if not server_valid:
                self.mail_server_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
                self.error_mail_server_input.setText("Error: Invalid server addres")
            else:
                self.mail_server_input.setStyleSheet("")
                self.error_mail_server_input.setText("")
            if not server_port_valid:
                self.mail_port_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
                self.error_mail_port_input.setText("Error: Invalid port")
            else:
                self.mail_port_input.setStyleSheet("")
                self.error_mail_port_input.setText("")
            if not password_valid:
                self.sender_password_input.setStyleSheet(
                    INPUT_FORM_ERROR_BACKGROUND_COLOR
                )
            else:
                self.sender_password_input.setStyleSheet("")

            if (
                sender_valid
                and receiver_valid
                and server_valid
                and server_port_valid
                and password_valid
            ):
                self.save_button.setEnabled(True)
                self.test_button.setEnabled(True)
            else:
                self.save_button.setEnabled(False)
                self.test_button.setEnabled(False)
        else:
            self.sender_mail_input.setStyleSheet("")
            self.receiver_mail_input.setStyleSheet("")
            self.mail_server_input.setStyleSheet("")
            self.mail_port_input.setStyleSheet("")
            self.sender_password_input.setStyleSheet("")
            self.save_button.setEnabled(True)

    def is_valid_email(self, email):
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(email_pattern, email)

    def save_config(self):
        config = {
            "mail_enabled": self.mail_enabled.isChecked(),
            "mail_server_address": self.mail_server_input.text(),
            "port_mail": self.mail_port_input.text(),
            "ssl_enabled": self.ssl_checkbox.isChecked(),
            "sender_mail": self.sender_mail_input.text(),
            "sender_password": self.sender_password_input.text(),
            "receiver_mail": self.receiver_mail_input.text(),
        }
        self.setting_manager.smtp_settings = config
        self.setting_manager.save_config()
        QMessageBox.information(
            self, "Success", "SMTP configuration saved successfully"
        )
        self.save_button.setEnabled(False)

    def is_valid_host(self, host):
        ip_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        hostname_pattern = r"^(?=.{1,255}$)[0-9A-Za-z](?:[0-9A-Za-z-]{0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]{0,61}[0-9A-Za-z])?)*$"
        try:
            if re.match(ip_pattern, host):
                return True
            elif re.match(hostname_pattern, host):
                return True
            else:
                return False
        except:
            return False

    def is_valid_port(self, port):
        try:
            port_num = int(port)
            if 0 < port_num <= 65535:
                return True
            else:
                return False
        except ValueError:
            return False

    def test_config(self):
        test_mail = MailSender(
            self.mail_server_input.text(),
            self.mail_port_input.text(),
            self.ssl_checkbox.isChecked(),
            self.sender_mail_input.text(),
            self.sender_password_input.text(),
            self.receiver_mail_input.text(),
        )
        try:
            test_mail.send_mail(
                self.receiver_mail_input.text(),
                "Test message from RedBee OPC Event Notifier",
            )
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "TestSMTP", "Error", QMessageBox.Critical
            )
        else:
            QMessageBox.information(self, "Success", "Test mail sent successfully")
        finally:
            test_mail = None


# SQL Settings widget for the user interface
class SQLSettingsWidget(QWidget):
    def __init__(self, setting_manager):
        super().__init__()
        self.setting_manager = setting_manager
        self.initUI()

    def initUI(self):
        self.sql_enabled = QCheckBox("SQL logging enabled")
        self.sql_enabled.clicked.connect(self.toggle_allow)
        self.sql_enabled.clicked.connect(self.setting_check)
        self.sql_enabled.setChecked(self.setting_manager.sql_settings["sql_enabled"])

        self.mssql_enabled = QCheckBox("Microsoft SQL Server enabled")
        self.mssql_enabled.setChecked(
            self.setting_manager.sql_settings["mssql_enabled"]
        )
        self.mssql_enabled.clicked.connect(self.toggle_mssql)
        self.mssql_enabled.clicked.connect(self.setting_check)

        self.mssql_server_label = QLabel("MSSQL Server Address:")
        self.mssql_server_input = QLineEdit(
            self.setting_manager.sql_settings["mssql_server_address"]
        )
        self.mssql_server_input.textChanged.connect(self.setting_check)

        self.mssql_port_label = QLabel("MSSQL Server Port:")
        self.mssql_port_input = QLineEdit(
            self.setting_manager.sql_settings["mssql_port"]
        )
        self.mssql_port_input.textChanged.connect(self.setting_check)

        self.mssql_db_label = QLabel("MSSQL Database:")
        self.mssql_db_input = QLineEdit(
            self.setting_manager.sql_settings["mssql_database_name"]
        )
        self.mssql_db_input.textChanged.connect(self.setting_check)

        self.mssql_user_label = QLabel("MSSQL Username:")
        self.mssql_user_input = QLineEdit(
            self.setting_manager.sql_settings["mssql_username"]
        )
        self.mssql_user_input.textChanged.connect(self.setting_check)

        self.mssql_password_label = QLabel("MSSQL Password:")
        self.mssql_password_input = QLineEdit(
            self.setting_manager.sql_settings["mssql_password"]
        )
        self.mssql_password_input.setEchoMode(QLineEdit.Password)
        self.mssql_password_input.textChanged.connect(self.setting_check)

        self.mysql_enabled = QCheckBox("MySQL Server enabled")
        self.mysql_enabled.setChecked(
            self.setting_manager.sql_settings["mysql_enabled"]
        )
        self.mysql_enabled.clicked.connect(self.toggle_mysql)
        self.mysql_enabled.clicked.connect(self.setting_check)

        self.mysql_server_label = QLabel("MySQL Server Address:")
        self.mysql_server_input = QLineEdit(
            self.setting_manager.sql_settings["mysql_server_address"]
        )
        self.mysql_server_input.textChanged.connect(self.setting_check)

        self.mysql_port_label = QLabel("MySQL Server Port:")
        self.mysql_port_input = QLineEdit(
            self.setting_manager.sql_settings["mysql_port"]
        )
        self.mysql_port_input.textChanged.connect(self.setting_check)

        self.mysql_db_label = QLabel("MySQL Database:")
        self.mysql_db_input = QLineEdit(
            self.setting_manager.sql_settings["mysql_database_name"]
        )
        self.mysql_db_input.textChanged.connect(self.setting_check)

        self.mysql_user_label = QLabel("MySQL Username:")
        self.mysql_user_input = QLineEdit(
            self.setting_manager.sql_settings["mysql_username"]
        )
        self.mysql_user_input.textChanged.connect(self.setting_check)

        self.mysql_password_label = QLabel("MySQL Password:")
        self.mysql_password_input = QLineEdit(
            self.setting_manager.sql_settings["mysql_password"]
        )
        self.mysql_password_input.setEchoMode(QLineEdit.Password)
        self.mysql_password_input.textChanged.connect(self.setting_check)

        self.test_button = QPushButton("Test")
        self.test_button.clicked.connect(self.test_config)
        self.test_button.setEnabled(True)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_config)
        self.save_button.setEnabled(False)

        # Create a horizontal layout for buttons
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.save_button)
        button_layout.setAlignment(Qt.AlignRight)

        # Main layout
        layout = QVBoxLayout()
        layout.addWidget(self.sql_enabled)
        layout.addWidget(self.mssql_enabled)
        layout.addWidget(self.mssql_server_label)
        layout.addWidget(self.mssql_server_input)
        layout.addWidget(self.mssql_port_label)
        layout.addWidget(self.mssql_port_input)
        layout.addWidget(self.mssql_db_label)
        layout.addWidget(self.mssql_db_input)
        layout.addWidget(self.mssql_user_label)
        layout.addWidget(self.mssql_user_input)
        layout.addWidget(self.mssql_password_label)
        layout.addWidget(self.mssql_password_input)
        layout.addWidget(self.mysql_enabled)
        layout.addWidget(self.mysql_server_label)
        layout.addWidget(self.mysql_server_input)
        layout.addWidget(self.mysql_port_label)
        layout.addWidget(self.mysql_port_input)
        layout.addWidget(self.mysql_db_label)
        layout.addWidget(self.mysql_db_input)
        layout.addWidget(self.mysql_user_label)
        layout.addWidget(self.mysql_user_input)
        layout.addWidget(self.mysql_password_label)
        layout.addWidget(self.mysql_password_input)
        layout.addLayout(button_layout)

        # Add spacing and alignment
        layout.addSpacing(10)
        layout.setAlignment(Qt.AlignTop)
        button_layout.setAlignment(Qt.AlignRight)

        self.setLayout(layout)
        self.toggle_allow()
        self.toggle_mssql()
        self.toggle_mysql()
        # self.setting_check()

    def toggle_allow(self):
        enabled = self.sql_enabled.isChecked()
        for widget in [self.mssql_enabled, self.mysql_enabled]:
            if not enabled:
                widget.setChecked(False)
            widget.setEnabled(enabled)
        for widget in [
            self.mssql_server_label,
            self.mssql_server_input,
            self.mssql_port_label,
            self.mssql_port_input,
            self.mssql_db_label,
            self.mssql_db_input,
            self.mssql_user_label,
            self.mssql_user_input,
            self.mssql_password_label,
            self.mssql_password_input,
            self.mysql_server_label,
            self.mysql_server_input,
            self.mysql_port_label,
            self.mysql_port_input,
            self.mysql_db_label,
            self.mysql_db_input,
            self.mysql_user_label,
            self.mysql_user_input,
            self.mysql_password_label,
            self.mysql_password_input,
        ]:
            widget.setEnabled(enabled)

    def toggle_mssql(self):
        enabled = self.mssql_enabled.isChecked()
        for widget in [
            self.mssql_server_label,
            self.mssql_server_input,
            self.mssql_port_label,
            self.mssql_port_input,
            self.mssql_db_label,
            self.mssql_db_input,
            self.mssql_user_label,
            self.mssql_user_input,
            self.mssql_password_label,
            self.mssql_password_input,
        ]:
            widget.setEnabled(enabled)

    def toggle_mysql(self):
        enabled = self.mysql_enabled.isChecked()
        for widget in [
            self.mysql_server_label,
            self.mysql_server_input,
            self.mysql_port_label,
            self.mysql_port_input,
            self.mysql_db_label,
            self.mysql_db_input,
            self.mysql_user_label,
            self.mysql_user_input,
            self.mysql_password_label,
            self.mysql_password_input,
        ]:
            widget.setEnabled(enabled)

    def setting_check(self):
        mysql_conf_ok = False
        mssql_conf_ok = False
        mssql_server_valid = self.is_valid_host(self.mssql_server_input.text())
        mssql_port_valid = self.is_valid_port(self.mssql_port_input.text())
        mssql_db_valid = bool(self.mssql_db_input.text().strip())
        mssql_user_valid = bool(self.mssql_user_input.text().strip())
        mssql_password_valid = bool(self.mssql_password_input.text().strip())
        if (
            mssql_server_valid
            and mssql_port_valid
            and mssql_db_valid
            and mssql_user_valid
        ):
            mssql_conf_ok = True

        mysql_server_valid = self.is_valid_host(self.mysql_server_input.text())
        mysql_port_valid = self.is_valid_port(self.mysql_port_input.text())
        mysql_db_valid = bool(self.mysql_db_input.text().strip())
        mysql_user_valid = bool(self.mysql_user_input.text().strip())
        mysql_password_valid = bool(self.mysql_password_input.text().strip())
        if (
            mysql_server_valid
            and mysql_port_valid
            and mysql_db_valid
            and mysql_user_valid
        ):
            mysql_conf_ok = True

        if mssql_conf_ok or mysql_conf_ok:
            self.test_button.setEnabled(True)
            if mssql_conf_ok and mysql_conf_ok:

                self.save_button.setEnabled(True)
            elif mssql_conf_ok and not self.mysql_enabled.isChecked():
                self.save_button.setEnabled(True)
            elif mysql_conf_ok and not self.mssql_enabled.isChecked():
                self.save_button.setEnabled(True)
            else:
                self.save_button.setEnabled(False)
        else:
            self.save_button.setEnabled(False)
            self.test_button.setEnabled(False)

        if self.mssql_enabled.isChecked():
            if not mssql_server_valid:
                self.mssql_server_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mssql_server_input.setStyleSheet("")
            if not mssql_port_valid:
                self.mssql_port_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mssql_port_input.setStyleSheet("")
            if not mssql_db_valid:
                self.mssql_db_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mssql_db_input.setStyleSheet("")
            if not mssql_user_valid:
                self.mssql_user_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mssql_user_input.setStyleSheet("")
        else:
            self.mssql_server_input.setStyleSheet("")
            self.mssql_port_input.setStyleSheet("")
            self.mssql_db_input.setStyleSheet("")
            self.mssql_user_input.setStyleSheet("")

        if self.mysql_enabled.isChecked():
            if not mysql_server_valid:
                self.mysql_server_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mysql_server_input.setStyleSheet("")
            if not mysql_port_valid:
                self.mysql_port_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mysql_port_input.setStyleSheet("")
            if not mysql_db_valid:
                self.mysql_db_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mysql_db_input.setStyleSheet("")
            if not mysql_user_valid:
                self.mysql_user_input.setStyleSheet(INPUT_FORM_ERROR_BACKGROUND_COLOR)
            else:
                self.mysql_user_input.setStyleSheet("")
        else:
            self.mysql_server_input.setStyleSheet("")
            self.mysql_port_input.setStyleSheet("")
            self.mysql_db_input.setStyleSheet("")
            self.mysql_user_input.setStyleSheet("")

    def save_config(self):
        config = {
            "sql_enabled": self.sql_enabled.isChecked(),
            "mssql_enabled": self.mssql_enabled.isChecked(),
            "mssql_server_address": self.mssql_server_input.text(),
            "mssql_port": self.mssql_port_input.text(),
            "mssql_database_name": self.mssql_db_input.text(),
            "mssql_username": self.mssql_user_input.text(),
            "mssql_password": self.mssql_password_input.text(),
            "mysql_enabled": self.mysql_enabled.isChecked(),
            "mysql_server_address": self.mysql_server_input.text(),
            "mysql_port": self.mysql_port_input.text(),
            "mysql_database_name": self.mysql_db_input.text(),
            "mysql_username": self.mysql_user_input.text(),
            "mysql_password": self.mysql_password_input.text(),
        }
        self.setting_manager.sql_settings = config
        self.setting_manager.save_config()
        QMessageBox.information(self, "Success", "SQL configuration saved successfully")
        self.save_button.setEnabled(False)

    def test_config(self):
        if self.mssql_enabled.isChecked() and self.mysql_enabled.isChecked():
            pass
        elif self.mysql_enabled.isChecked():
            test_mysql = SqlHandler(
                self.mysql_server_input.text(),
                self.mysql_port_input.text(),
                self.mysql_db_input.text(),
                self.mysql_user_input.text(),
                self.mysql_password_input.text(),
            )
            try:
                test_mysql.connect_to_mysql()
            except Exception as e:
                ExceptionHandler.handle_exception(
                    str(e), "TestSQL", "Error", QMessageBox.Critical
                )
            else:
                QMessageBox.information(self, "Success", "Connection successful")
                test_mysql.disconnect_from_mysql()
            finally:
                test_mysql = None
        elif self.mssql_enabled.isChecked():
            test_mssql = SqlHandler(
                self.mysql_server_input.text(),
                self.mysql_port_input.text(),
                self.mysql_db_input.text(),
                self.mysql_user_input.text(),
                self.mysql_password_input.text(),
            )
            try:
                test_mssql.connect_to_mssql()
            except Exception as e:
                ExceptionHandler.handle_exception(
                    str(e), "TestSQL", "Error", QMessageBox.Critical
                )
            else:
                QMessageBox.information(self, "Success", "Connection successful")
                test_mssql.disconnect_from_mssql()
            finally:
                test_mssql = None

    def is_valid_host(self, host):
        ip_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        hostname_pattern = r"^(?=.{1,255}$)[0-9A-Za-z](?:[0-9A-Za-z-]{0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:[0-9A-Za-z-]{0,61}[0-9A-Za-z])?)*$"
        try:
            if re.match(ip_pattern, host):
                return True
            elif re.match(hostname_pattern, host):
                return True
            else:
                return False
        except:
            return False

    def is_valid_port(self, port):
        try:
            port_num = int(port)
            if 0 < port_num <= 65535:
                return True
            else:
                return False
        except ValueError:
            return False


# --------------------Messages---------------------#
# Default information message for the user interface
class InfoMessage:
    def __init__(self):
        pass

    @staticmethod
    def show_info_message(
        message,
        title="Info",
        icon=QMessageBox.Information,
        buttons=QMessageBox.Ok,
        width=INFO_MESSAGE_SIZE[0],
        height=INFO_MESSAGE_SIZE[1],
    ):
        info_box = QMessageBox()
        info_box.setWindowTitle(title)
        info_box.setIcon(icon)
        info_box.setStandardButtons(buttons)
        info_box.setDefaultButton(QMessageBox.Ok)
        info_box.setText(message)
        info_box.setGeometry(*INFO_MESSAGE_POSITION, width, height)
        info_box.setFixedSize(width, height)
        info_box.exec()


# Round indicator for the user interface
class RoundIndicator(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(*ROUND_INDICATOR_SIZE)
        self.setMaximumSize(*ROUND_INDICATOR_SIZE)
        # set a thin circular black border
        self.color = Qt.red

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(Qt.black, 1, Qt.SolidLine))
        painter.setBrush(QBrush(self.color))
        painter.drawEllipse(0, 0, self.width(), self.height())