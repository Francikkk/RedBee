# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from exception_handler import ExceptionHandler
from constants import (
    AUTHENTICATION_DIRECTORY,
    AUTH_FILE,
    ENCRYPTION_KEY_PATH,
    PRIVILEGES_LIST,
    INITIAL_USERS,
    INITIAL_ROLES,
    LOGIN_DIALOG_TITLE,
    USER_MANAGER_REMOVE_TITLE,
    USER_MANAGER_ADD_TITLE,
    USER_MANAGER_INITIAL_POSITION,
    USER_MANAGER_REMOVE_SIZE,
    USER_MANAGER_ADD_SIZE,
    USER_MANAGER_APPLICATION_DOMAIN,
    ROLE_MANAGER_REMOVE_TITLE,
    ROLE_MANAGER_ADD_TITLE,
    ROLE_MANAGER_INITIAL_POSITION,
    ROLE_MANAGER_REMOVE_SIZE,
    ROLE_MANAGER_ADD_SIZE,
    ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY,
    UNLOCK_USER_DIALOG_TITLE,
    ICON_UNLOCK_USER,
    ICON_USER,
    USER_MANAGER_APPLICATION_DOMAIN,
)

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
import datetime
import os
import sys
import json
import win32security
import pywintypes
import win32api
import win32net
import win32netcon
import win32security
from cryptography.fernet import Fernet
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QSizePolicy,
    QSpacerItem,
    QListWidget,
    QGridLayout,
)
from PySide6.QtGui import QIcon, QStandardItem
from PySide6.QtCore import QThread, Signal


# Authentication and authorization handler for user login and role-based access control
class AuthenticationManager:
    """
    AuthenticationManager
    Description:
    The AuthenticationManager class is responsible for managing user authentication and authorization.

    Responsibilities:
    Authenticate users with a username and password.
    Authorize users based on their role.

    Attributes:
    users: Dictionary of users with their usernames, roles, and passwords.
    roles: Dictionary of roles with their permissions.

    Interfaces:
    authenticate(username, password): Authenticates a user with a username and password.
    authorize(user, permission): Authorizes a user based on their role and the required permission.
    """

    def __init__(
        self,
        authentication_enabled=False,
        lock_timer_enabled=False,
        lock_timer_value=30,
    ):
        self.active_user = None
        self.login_time = None
        self.credential_directory = AUTHENTICATION_DIRECTORY
        self.credential_file_path = AUTH_FILE
        self.key_path = ENCRYPTION_KEY_PATH
        self.load_key()
        self.authentication_enabled = authentication_enabled
        self.lock_timer_enabled = lock_timer_enabled
        self.lock_timer_value = lock_timer_value
        self.auto_logout_interval = 10
        self.auto_logout_worker = AutoLockActiveUser(10)
        self.auto_logout_worker.timeout_signal.connect(self.check_auto_logout)
        self.privileges = PRIVILEGES_LIST
        self.users = INITIAL_USERS
        self.roles = INITIAL_ROLES
        self.user_manager_dialog = None
        self.role_manager_dialog = None
        self.init()

    def init(self):
        if not os.path.exists(self.credential_directory):
            os.makedirs(self.credential_directory)
        if not os.path.exists(self.credential_file_path):
            self.save()
        else:
            with open(self.credential_file_path, "r") as f:
                data = json.load(f)
                self.users = {
                    user: {
                        "role": user_data["role"],
                        "password": self.decrypt_password(user_data["password"]),
                        "domain": user_data["domain"],
                    }
                    for user, user_data in data["users"].items()
                }
                self.roles = data["roles"]
        if self.authentication_enabled:
            try:
                app = QApplication.instance()
                if not app:
                    app = QApplication(sys.argv)
                app.setStyle("Fusion")
            except Exception as e:
                ExceptionHandler.unhandled_exception(e, "AuthenticationManager")
            else:
                verifier = self.login()
                if not verifier:
                    sys.exit()
        if self.lock_timer_enabled:
            self.auto_logout_worker.start()

    def load_key(self):
        with open(self.key_path, "rb") as key_file:
            self.key = key_file.read()

    def encrypt_password(self, password):
        cipher_suite = Fernet(self.key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return encrypted_password.decode("utf-8")

    def decrypt_password(self, encrypted_password):
        cipher_suite = Fernet(self.key)
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        return decrypted_password

    def check_auto_logout(self):
        if self.active_user and self.login_time:
            elapsed_time = (datetime.datetime.now() - self.login_time).total_seconds()
            if elapsed_time > self.auto_logout_interval:
                self.auto_logout()

    def auto_logout(self):
        username = self.active_user
        self.logout()
        QMessageBox.information(
            None,
            "Auto Logout",
            f"User {username} has been logged out due to inactivity.",
        )
        self.require_reauthentication(username)

    def require_reauthentication(self, username):
        while True:
            login_dialog = UnlockUserDialog(username)
            if login_dialog.exec() == QDialog.Accepted:
                _, password = login_dialog.get_credentials()
                if self.check_credentials(username, password):
                    if "\\" in username:
                        self.active_user = username
                    else:
                        self.active_user = username
                    self.login_time = datetime.datetime.now()
                    QMessageBox.information(
                        None,
                        "Authentication Success",
                        "You have successfully authenticated!",
                    )
                    return
                else:
                    QMessageBox.critical(
                        None, "Authentication Failed", "Invalid password."
                    )
            else:
                QMessageBox.warning(None, "Cancelled", "Authentication cancelled.")
                self.auto_logout_worker.stop()
                self.auto_logout_worker.wait()

    def login(self, succes_dialog=False, login=True):
        login_dialog = LoginDialog()
        if login:
            while True:
                if login_dialog.exec() == QDialog.Accepted:
                    username, password = login_dialog.get_credentials()
                    if self.check_credentials(username, password):
                        self.active_user = username
                        self.login_time = datetime.datetime.now()
                        if succes_dialog:
                            QMessageBox.information(
                                None,
                                "Login Success",
                                "You have successfully logged in!",
                            )
                        return True
                    else:
                        QMessageBox.critical(
                            None, "Login Failed", "Invalid username or password."
                        )
                else:
                    QMessageBox.warning(None, "Cancelled", "Login cancelled.")
                    return False
        else:
            pass

    def authentication(self):
        login_dialog = LoginDialog()
        while True:
            if login_dialog.exec() == QDialog.Accepted:
                username, password = login_dialog.get_credentials()
                if self.check_credentials(username, password):
                    if self.active_user is None:
                        self.active_user = username
                        self.login_time = datetime.datetime.now()
                        QMessageBox.information(
                            None, "Authentication success", "Authentication enabled!"
                        )
                    else:
                        self.active_user = None
                        self.login_time = None
                        QMessageBox.information(
                            None, "Authentication success", "Authentication disabled!"
                        )
                    return True
                else:
                    QMessageBox.critical(
                        None,
                        "Invalid credentials",
                        "Username or password is not correct!",
                    )
            else:
                QMessageBox.warning(None, "Cancelled", "Authentication cancelled.")
                return False

    def check_credentials(self, username, password):
        print (f"Username: {username}, Password: {password}")
        if "\\" in username:
            domain, username = username.split("\\")
            if domain == USER_MANAGER_APPLICATION_DOMAIN:
                if username in self.users:
                    if self.users[username]["password"] == password:
                        return True
            else:
                if domain == ".":
                    # In this case the domain is the local host
                    domain = win32api.GetComputerName()
                try:
                    user_token = win32security.LogonUser(
                        username,
                        domain,
                        password,
                        win32security.LOGON32_LOGON_INTERACTIVE,
                        win32security.LOGON32_PROVIDER_DEFAULT,
                    )
                    win32security.ImpersonateLoggedOnUser(user_token)
                    win32security.RevertToSelf()
                    return True
                except Exception as e:
                    QMessageBox.critical(None, "Error", f"Failed to authenticate user: {e}")
                    return False
        else:
            domain = USER_MANAGER_APPLICATION_DOMAIN
            if username in self.users:
                if self.users[username]["password"] == password:
                    return True
        return False

    def logout(self):
        self.active_user = None
        self.login_time = None

    def authorize(self, user, permission):
        if user in self.users:
            user_role = self.users[user]["role"]
            if permission in self.roles.get(user_role, ""):
                return True
        return False

    def save(self):
        data = {
            "users": {
                user: {
                    "role": user_data["role"],
                    "password": self.encrypt_password(user_data["password"]),
                    "domain": user_data["domain"],
                }
                for user, user_data in self.users.items()
            },
            "roles": self.roles,
        }
        with open(self.credential_file_path, "w") as f:
            json.dump(data, f)

    def get_user_role(self):
        if self.active_user:
            if ".\\" in self.active_user:
                domain = win32api.GetComputerName()
                username = self.active_user.split("\\")[1]
                return self.users[f"{domain}\\{username}"]["role"]
            return self.users[self.active_user]["role"]
        return None

    def add_or_update_user(self, username, password, role, domain):
        current_registered_users = [f"{user_data['domain']}\\{user}" for user, user_data in self.users.items()]
        user_key = f"{domain}\\{username}"

        if domain != USER_MANAGER_APPLICATION_DOMAIN:
            self.users[f"{domain}\\{username}"] = {"role": role, "password": password, "domain": domain}
        else:
            self.users[username] = {"role": role, "password": password, "domain": domain}
        self.save()

    def delete_user(self, username):
        if username in self.users:
            del self.users[username]
        self.save()

    def show_add_user_dialog(self, parent):
        self.user_manager_dialog = UserManager(self, parent, remove_mode=False)
        self.user_manager_dialog.exec_()

    def show_remove_user_dialog(self, parent):
        self.user_manager_dialog = UserManager(self, parent, remove_mode=True)
        self.user_manager_dialog.exec_()

    def show_add_role_dialog(self, parent):
        self.role_manager_dialog = RoleManager(self, parent, remove_mode=False)
        self.role_manager_dialog.exec_()

    def show_remove_role_dialog(self, parent):
        self.role_manager_dialog = RoleManager(self, parent, remove_mode=True)
        self.role_manager_dialog.exec_()

    def add_or_update_role(self, role, permissions):
        self.roles[role] = permissions
        self.save()

    def delete_role(self, role):
        if role in self.roles:
            del self.roles[role]
        self.save()

    def __del__(self):
        self.auto_logout_worker.stop()
        self.auto_logout_worker.wait()


# Manage the auto lock of the active user
class AutoLockActiveUser(QThread):
    timeout_signal = Signal()

    def __init__(self, interval):
        super().__init__()
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            self.msleep(self.interval * 1000)
            if self.running:
                self.timeout_signal.emit()

    def stop(self):
        self.running = False
        self.wait()


# Ask for credentials to login
class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(LOGIN_DIALOG_TITLE)
        self.setWindowIcon(QIcon(ICON_USER))
        self.setFixedSize(300, 150)
        self.username = self.password = ""
        layout = QVBoxLayout()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.ok_button.setEnabled(False)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)

    def get_credentials(self):
        username = self.username_input.text()
        password = self.password_input.text()
        return username, password

    def save_toggle(self):
        if self.username_input.text() and self.password_input.text():
            self.ok_button.setEnabled(True)
        else:
            self.ok_button.setEnabled(False)


# User Management class to handle adding and removing users
class UserManager(QDialog):
    def __init__(self, auth_handler, parent=None, remove_mode=False):
        super().__init__(parent)
        self.auth_handler = auth_handler
        self.remove_mode = remove_mode
        self.win_operation = False
        self.initUI()

    def initUI(self):
        self.layout = QGridLayout()

        if self.remove_mode:
            self.setWindowTitle(USER_MANAGER_REMOVE_TITLE)
            self.setGeometry(*USER_MANAGER_INITIAL_POSITION, *USER_MANAGER_REMOVE_SIZE)
            self.setMinimumSize(*USER_MANAGER_REMOVE_SIZE)

            self.user_combo = QComboBox()
            for username, user_data in self.auth_handler.users.items():
                self.user_combo.addItem(f"{username} ({user_data['role']})", username)

            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            button_box.accepted.connect(self.remove_user)
            button_box.rejected.connect(self.reject)

            self.layout.addWidget(QLabel("Select user to remove:"), 0, 0)
            self.layout.addWidget(self.user_combo, 0, 1)
            self.layout.addWidget(button_box, 2, 0, 1, 2)

        else:
            self.setWindowTitle(USER_MANAGER_ADD_TITLE)
            self.setGeometry(*USER_MANAGER_INITIAL_POSITION, *USER_MANAGER_ADD_SIZE)
            self.setMinimumSize(*USER_MANAGER_ADD_SIZE)

            self.domain_selection_checkbox = QCheckBox("Use Windows Domain")
            self.domain_selection_checkbox.setChecked(False)
            self.domain_selection_checkbox.stateChanged.connect(self.domain_selection_checkbox_state_changed)

            self.username_label = QLabel("Username:")
            self.username_input = QLineEdit()

            self.role_label = QLabel("Role:")
            self.role_combo = QComboBox()
            self.role_combo.addItems(self.auth_handler.roles.keys())

            self.password_label = QLabel("Password:")
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.Password)

            self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            self.button_box.accepted.connect(self.accept)
            self.button_box.rejected.connect(self.reject)

            self.add_user_widgets()

        self.setLayout(self.layout)

    def clear_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            if child.layout():
                self.clear_layout(child.layout())

    def add_user_widgets(self):
        self.win_operation = False
        self.layout.addWidget(self.domain_selection_checkbox, 0, 0, 1, 2)
        self.layout.addWidget(self.username_label, 1, 0)
        self.layout.addWidget(self.username_input, 1, 1)
        self.layout.addWidget(self.role_label, 2, 0)
        self.layout.addWidget(self.role_combo, 2, 1)
        self.layout.addWidget(self.password_label, 3, 0)
        self.layout.addWidget(self.password_input, 3, 1)
        self.layout.addWidget(self.button_box, 4, 0, 1, 2)

    def add_domain_widgets(self):
        self.win_operation = True
        self.username_input = QLineEdit()
        self.user_list = QListWidget()
        self.username_input.textChanged.connect(self.update_user_list)
        self.role_combo = QComboBox()
        self.role_combo.addItems(self.auth_handler.roles.keys())

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        self.layout.addWidget(QLabel("Username:"), 1, 0)
        self.layout.addWidget(self.username_input, 1, 1)
        self.layout.addWidget(QLabel(""), 2, 0)
        self.layout.addWidget(self.user_list, 2, 1)
        self.layout.addWidget(QLabel("Role:"), 3, 0)
        self.layout.addWidget(self.role_combo, 3, 1)
        self.layout.addWidget(self.button_box, 4, 0, 1, 2)

    def update_user_list(self):
        search_text = self.username_input.text()
        self.user_list.clear()

        if search_text:
            local_users = self.get_local_users(search_text)
            domain_users = self.get_domain_users(search_text)

            all_users = local_users + domain_users
            all_users = [user for user in all_users if user not in self.auth_handler.users]
            self.user_list.addItems(all_users)

    def get_local_users(self, search_text):
        try:
            local_users = []
            pc_name = win32api.GetComputerName()
            search_text_lower = search_text.lower()
            resume_handle = 0
            while True:
                users, _, resume_handle = win32net.NetUserEnum(
                    None,
                    0,
                    win32netcon.FILTER_NORMAL_ACCOUNT,
                    resume_handle,
                    win32netcon.MAX_PREFERRED_LENGTH
                )
                for user in users:
                    username = user['name']
                    username_lower = username.lower()
                    if username_lower.startswith(search_text_lower) or pc_name.lower().startswith(search_text_lower):
                        local_users.append(f"{pc_name}\\{username}")
                if resume_handle == 0:
                    break
            return local_users
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to fetch local users: {e}")
            return []

    def get_domain_users(self, search_text):
        try:
            domain_users = []
            domain_controller = win32net.NetGetAnyDCName()
            resume_handle = 0
            while True:
                users, _, resume_handle = win32net.NetUserEnum(
                    domain_controller,
                    0,
                    win32netcon.FILTER_NORMAL_ACCOUNT,
                    resume_handle,
                    win32netcon.MAX_PREFERRED_LENGTH
                )
                for user in users:
                    username = user['name']
                    if search_text.lower() in username.lower():
                        domain_users.append(f"{domain_controller}\\{username}")
                if resume_handle == 0:
                    break
            return domain_users
        except Exception as e:
            pass
            # Uncomment the following line to show a diagnostic message
            # QMessageBox.critical(self, "Error", f"Failed to fetch domain users: {e}")
            return []

    def domain_selection_checkbox_state_changed(self):
        # Clear the layout
        self.clear_layout(self.layout)

        # Re-add the checkbox to the layout
        self.layout.addWidget(self.domain_selection_checkbox, 0, 0, 1, 2)

        # Add the appropriate widgets based on the checkbox state
        if self.domain_selection_checkbox.isChecked():
            self.add_domain_widgets()
        else:
            self.add_user_widgets()

    def accept(self):
        if self.remove_mode:
            self.remove_user()
        else:
            if self.win_operation:
                full_username = self.user_list.currentItem().text()
                domain, username = full_username.split("\\")
                role = self.role_combo.currentText()
                password = ""
                current_registered_users = [f"{user_data['domain']}\\{user}" for user, user_data in self.auth_handler.users.items()]

                if username:
                    if full_username in current_registered_users:
                        QMessageBox.warning(self, "Input Error", "User already exists.")
                    else:
                        self.auth_handler.add_or_update_user(
                            username, password, role, domain
                        )
                        self.parent().model.appendRow(
                            [QStandardItem(username), QStandardItem(role)]
                        )
                    super().accept()
                else:
                    QMessageBox.warning(
                        self, "Input Error", "Username and password cannot be empty."
                    )
            else:
                username = self.username_input.text()
                role = self.role_combo.currentText()
                password = self.password_input.text()
                domain = USER_MANAGER_APPLICATION_DOMAIN
                current_registered_users = [f"{user_data['domain']}\\{user}" for user, user_data in self.auth_handler.users.items()]

                if username and password:
                    if f"{domain}\\{username}" in current_registered_users:
                        QMessageBox.warning(self, "Input Error", "User already exists.")
                    else:
                        self.auth_handler.add_or_update_user(
                            username, password, role, domain
                        )
                        self.parent().model.appendRow(
                            [QStandardItem(username), QStandardItem(role)]
                        )
                    super().accept()
                else:
                    QMessageBox.warning(
                        self, "Input Error", "Username and password cannot be empty."
                    )

    def remove_user(self):
        username = self.user_combo.currentData()
        if username:
            self.auth_handler.delete_user(username)
            self.parent().model.removeRow(self.user_combo.currentIndex())
            super().accept()


# Role Management class to handle adding and removing roles
class RoleManager(QDialog):
    def __init__(self, auth_handler, parent=None, remove_mode=False):
        super().__init__(parent)
        self.auth_handler = auth_handler
        self.remove_mode = remove_mode
        self.initUI()

    def initUI(self):
        if self.remove_mode:
            self.setWindowTitle(ROLE_MANAGER_REMOVE_TITLE)
            self.setGeometry(*ROLE_MANAGER_INITIAL_POSITION, *ROLE_MANAGER_REMOVE_SIZE)
            self.setMinimumSize(*ROLE_MANAGER_REMOVE_SIZE)

            layout = QVBoxLayout()

            self.role_combo = QComboBox()
            for role in self.auth_handler.roles.keys():
                self.role_combo.addItem(role)

            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            button_box.accepted.connect(self.remove_role)
            button_box.rejected.connect(self.reject)

            layout.addWidget(QLabel("Select role to remove:"))
            layout.addWidget(self.role_combo)
            layout.addWidget(button_box)

            self.setLayout(layout)
        else:
            self.setWindowTitle(ROLE_MANAGER_ADD_TITLE)
            self.setGeometry(*ROLE_MANAGER_INITIAL_POSITION, *ROLE_MANAGER_ADD_SIZE)
            self.setMinimumSize(*ROLE_MANAGER_ADD_SIZE)

            layout = QVBoxLayout()

            self.role_label = QLabel("Role name:")
            self.role_name = QLineEdit()

            # Separation lines
            line = QFrame()
            line.setFrameShape(QFrame.HLine)
            line.setFrameShadow(QFrame.Sunken)

            # Privileges section
            self.privilege_checkboxes = {}
            for privilege in self.auth_handler.privileges:
                checkbox = QCheckBox(privilege)
                self.privilege_checkboxes[privilege] = checkbox

            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            button_box.accepted.connect(self.accept)
            button_box.rejected.connect(self.reject)

            layout.addWidget(self.role_label)
            layout.addWidget(self.role_name)
            layout.addWidget(line)
            for checkbox in self.privilege_checkboxes.values():
                if checkbox.text() == "Start":
                    layout.addWidget(QLabel("Main Window"))
                elif checkbox.text() == "General":
                    layout.addWidget(line)
                    layout.addWidget(QLabel("Settings"))
                elif checkbox.text() == "View user window":
                    layout.addWidget(line)
                    layout.addWidget(QLabel("User Management"))
                elif checkbox.text() == "View certificate window":
                    layout.addWidget(line)
                    layout.addWidget(QLabel("Certificate Management"))
                elif checkbox.text() == "View alarm log window":
                    layout.addWidget(line)
                    layout.addWidget(QLabel("Alarm Log"))
                h_layout = QHBoxLayout()
                spacer = QSpacerItem(20, 0, QSizePolicy.Minimum, QSizePolicy.Expanding)
                h_layout.addItem(spacer)
                h_layout.addWidget(checkbox)
                layout.addLayout(h_layout)

            layout.addWidget(button_box)

            self.setLayout(layout)

            # Connect signals to handlers
            self.connect_checkbox_signals()

    def connect_checkbox_signals(self):
        user_privileges = [
            "Add user",
            "Edit user",
            "Remove user",
            "Add role",
            "Edit role",
            "Remove role",
        ]
        certificate_privileges = ["Regenerate certificate", "Open certificate location"]
        alarm_log_privileges = ["Export alarm log"]

        for privilege in user_privileges:
            self.privilege_checkboxes[privilege].stateChanged.connect(
                self.update_view_user_window_checkbox
            )
        for privilege in certificate_privileges:
            self.privilege_checkboxes[privilege].stateChanged.connect(
                self.update_view_certificate_window_checkbox
            )
        for privilege in alarm_log_privileges:
            self.privilege_checkboxes[privilege].stateChanged.connect(
                self.update_view_alarm_log_window_checkbox
            )

        self.privilege_checkboxes["View user window"].stateChanged.connect(
            self.update_user_privileges_checkboxes
        )
        self.privilege_checkboxes["View certificate window"].stateChanged.connect(
            self.update_certificate_privileges_checkboxes
        )
        self.privilege_checkboxes["View alarm log window"].stateChanged.connect(
            self.update_alarm_log_privileges_checkboxes
        )

    def update_view_user_window_checkbox(self):
        if any(
            self.privilege_checkboxes[privilege].isChecked()
            for privilege in [
                "Add user",
                "Edit user",
                "Remove user",
                "Add role",
                "Edit role",
                "Remove role",
            ]
        ):
            self.privilege_checkboxes["View user window"].blockSignals(True)
            self.privilege_checkboxes["View user window"].setChecked(True)
            self.privilege_checkboxes["View user window"].blockSignals(False)

    def update_view_certificate_window_checkbox(self):
        if any(
            self.privilege_checkboxes[privilege].isChecked()
            for privilege in ["Regenerate certificate", "Open certificate location"]
        ):
            self.privilege_checkboxes["View certificate window"].blockSignals(True)
            self.privilege_checkboxes["View certificate window"].setChecked(True)
            self.privilege_checkboxes["View certificate window"].blockSignals(False)

    def update_view_alarm_log_window_checkbox(self):
        if self.privilege_checkboxes["Export alarm log"].isChecked():
            self.privilege_checkboxes["View alarm log window"].blockSignals(True)
            self.privilege_checkboxes["View alarm log window"].setChecked(True)
            self.privilege_checkboxes["View alarm log window"].blockSignals(False)

    def update_user_privileges_checkboxes(self):
        if not self.privilege_checkboxes["View user window"].isChecked():
            for privilege in [
                "Add user",
                "Edit user",
                "Remove user",
                "Add role",
                "Edit role",
                "Remove role",
            ]:
                self.privilege_checkboxes[privilege].blockSignals(True)
                self.privilege_checkboxes[privilege].setChecked(False)
                self.privilege_checkboxes[privilege].blockSignals(False)

    def update_certificate_privileges_checkboxes(self):
        if not self.privilege_checkboxes["View certificate window"].isChecked():
            for privilege in ["Regenerate certificate", "Open certificate location"]:
                self.privilege_checkboxes[privilege].blockSignals(True)
                self.privilege_checkboxes[privilege].setChecked(False)
                self.privilege_checkboxes[privilege].blockSignals(False)

    def update_alarm_log_privileges_checkboxes(self):
        if not self.privilege_checkboxes["View alarm log window"].isChecked():
            self.privilege_checkboxes["Export alarm log"].blockSignals(True)
            self.privilege_checkboxes["Export alarm log"].setChecked(False)
            self.privilege_checkboxes["Export alarm log"].blockSignals(False)

    def accept(self):
        if self.remove_mode:
            self.remove_role()
        else:
            role = self.role_name.text()

            if role:
                if role in self.auth_handler.roles:
                    QMessageBox.warning(self, "Input Error", "Role already exists.")
                else:
                    for privilege, checkbox in self.privilege_checkboxes.items():
                        if checkbox.isChecked():
                            if privilege in ["Start", "Stop"]:
                                ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY["Main"].append(
                                    privilege
                                )
                            elif privilege in [
                                "General",
                                "OPC",
                                "Alarm",
                                "Twilio",
                                "SMTP",
                            ]:
                                ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY[
                                    "Settings"
                                ].append(privilege)
                            elif privilege in [
                                "View user window",
                                "Add user",
                                "Edit user",
                                "Remove user",
                                "Add role",
                                "Edit role",
                                "Remove role",
                            ]:
                                ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY[
                                    "User_manager"
                                ].append(privilege)
                            elif privilege in [
                                "View certificate window",
                                "Regenerate certificate",
                                "Open certificate location",
                            ]:
                                ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY[
                                    "Certificate"
                                ].append(privilege)
                            elif privilege in [
                                "View alarm log window",
                                "Export alarm log",
                            ]:
                                ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY[
                                    "Alarm Log"
                                ].append(privilege)

                    self.auth_handler.add_or_update_role(
                        role, ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY
                    )
                    self.parent().model.appendRow([QStandardItem(role)])
                super().accept()
            else:
                QMessageBox.warning(self, "Input Error", "Role name can't be empty.")

    def remove_role(self):
        role = self.role_combo.currentText()
        if role:
            self.auth_handler.delete_role(role)
            self.parent().model.removeRow(self.role_combo.currentIndex())
            super().accept()


# Unlock user dialog to re-authenticate
class UnlockUserDialog(QDialog):
    def __init__(self, username=None):
        super().__init__()

        self.username = username

        self.setWindowTitle(UNLOCK_USER_DIALOG_TITLE)
        self.setWindowIcon(QIcon(ICON_UNLOCK_USER))
        self.setModal(True)

        self.layout = QVBoxLayout()

        if self.username:
            self.username_label = QLabel(f"Username: {self.username}")
            self.layout.addWidget(self.username_label)

        self.password_label = QLabel("Password:")
        self.layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.buttons_layout = QHBoxLayout()

        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.buttons_layout.addWidget(self.ok_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.buttons_layout.addWidget(self.cancel_button)

        self.layout.addLayout(self.buttons_layout)

        self.setLayout(self.layout)

    def get_credentials(self):
        return self.username, self.password_input.text()
