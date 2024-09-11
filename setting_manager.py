# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from authentication_manager import AuthenticationManager
from constants import (
    CONFIGURATION_FILE_PATH,
    ENCRYPTION_KEY_PATH,
    INITIAL_CONFIGURATION,
)

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
import datetime
import base64
import os
import json
from cryptography.fernet import Fernet


# Manage the settings of the application
class SettingManager:
    """
    SettingManager
    Description:
    The SettingManager class manages the settings of the application, including OPC server settings,
    alarm thresholds, Twilio settings for SMS notifications, and SMTP settings for email notifications.

    Responsibilities:
    Load and save configuration settings to a JSON file.
    Provide methods for adding, removing, and notifying observers of settings updates.

    Attributes:
    observers: List of observers to be notified of settings updates.
    opc_settings: OPC server settings.
    alarm_subscription: Alarm notification threshold settings.
    twilio_settings: Twilio settings for SMS notifications.
    smtp_settings: SMTP settings for email notifications.
    default_config: Default configuration settings.

    Interfaces:
    load_config(): Loads configuration settings from a JSON file.
    save_config(): Saves configuration settings to a JSON file.
    create_config(): Creates a default configuration file if none exists.
    add_observer(observer): Adds an observer to the list of observers.
    remove_observer(observer): Removes an observer from the list of observers.
    notify_observers(): Notifies all observers of settings updates.
    """

    def __init__(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: initializing.."
        )
        self.observers = []
        self.general_settings = {}
        self.opc_settings = {}
        self.alarm_subscription = {}
        self.twilio_settings = {}
        self.smtp_settings = {}
        self.sql_settings = {}
        self.default_config = INITIAL_CONFIGURATION
        self.key_path = ENCRYPTION_KEY_PATH
        self.load_or_generate_key()
        if not os.path.exists(CONFIGURATION_FILE_PATH):
            self.create_config()
        self.load_config()
        self.auth_handler = AuthenticationManager(
            authentication_enabled=self.general_settings["authentication"],
            lock_timer_enabled=self.general_settings["lock_timer"],
            lock_timer_value=self.general_settings["lock_timer_value"],
        )
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Initialized!"
        )

    def load_or_generate_key(self):
        if not os.path.exists(self.key_path):
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as key_file:
                key_file.write(key)
        with open(self.key_path, "rb") as key_file:
            self.key = key_file.read()

    def encrypt_password(self, password):
        cipher_suite = Fernet(self.key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        cipher_suite = Fernet(self.key)
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
        return decrypted_password

    def load_config(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Loading Config.."
        )
        with open(CONFIGURATION_FILE_PATH, "r") as f:
            config = json.load(f)
        self.general_settings = config["general_settings"]
        self.opc_settings = config["opc_settings"]
        self.alarm_subscription = config["alarm_subscription"]
        self.twilio_settings = config["twilio_settings"]
        self.smtp_settings = config["smtp_settings"]
        self.sql_settings = config["sql_settings"]
        self.opc_settings["password"] = self.decrypt_password(
            base64.b64decode(self.opc_settings["password"])
        )
        self.twilio_settings["twilio_auth_token"] = self.decrypt_password(
            base64.b64decode(self.twilio_settings["twilio_auth_token"])
        )
        self.smtp_settings["sender_password"] = self.decrypt_password(
            base64.b64decode(self.smtp_settings["sender_password"])
        )
        self.sql_settings["mssql_password"] = self.decrypt_password(
            base64.b64decode(self.sql_settings["mssql_password"])
        )
        self.sql_settings["mysql_password"] = self.decrypt_password(
            base64.b64decode(self.sql_settings["mysql_password"])
        )
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Config Loaded!"
        )

    def save_config(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Saving Config.."
        )
        self.opc_settings["password"] = base64.b64encode(
            self.encrypt_password(self.opc_settings["password"])
        ).decode("utf-8")
        self.twilio_settings["twilio_auth_token"] = base64.b64encode(
            self.encrypt_password(self.twilio_settings["twilio_auth_token"])
        ).decode("utf-8")
        self.smtp_settings["sender_password"] = base64.b64encode(
            self.encrypt_password(self.smtp_settings["sender_password"])
        ).decode("utf-8")
        self.sql_settings["mssql_password"] = base64.b64encode(
            self.encrypt_password(self.sql_settings["mssql_password"])
        ).decode("utf-8")
        self.sql_settings["mysql_password"] = base64.b64encode(
            self.encrypt_password(self.sql_settings["mysql_password"])
        ).decode("utf-8")
        config = {
            "general_settings": self.general_settings,
            "opc_settings": self.opc_settings,
            "alarm_subscription": self.alarm_subscription,
            "twilio_settings": self.twilio_settings,
            "smtp_settings": self.smtp_settings,
            "sql_settings": self.sql_settings,
        }
        with open(CONFIGURATION_FILE_PATH, "w") as f:
            json.dump(config, f)
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Config Saved!"
        )
        self.load_config()
        self.notify_observers()

    def create_config(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Creating Config.."
        )
        self.default_config["opc_settings"]["password"] = base64.b64encode(
            self.encrypt_password(self.default_config["opc_settings"]["password"])
        ).decode("utf-8")
        self.default_config["twilio_settings"]["twilio_auth_token"] = base64.b64encode(
            self.encrypt_password(
                self.default_config["twilio_settings"]["twilio_auth_token"]
            )
        ).decode("utf-8")
        self.default_config["smtp_settings"]["sender_password"] = base64.b64encode(
            self.encrypt_password(
                self.default_config["smtp_settings"]["sender_password"]
            )
        ).decode("utf-8")
        self.default_config["sql_settings"]["mssql_password"] = base64.b64encode(
            self.encrypt_password(self.default_config["sql_settings"]["mssql_password"])
        ).decode("utf-8")
        self.default_config["sql_settings"]["mysql_password"] = base64.b64encode(
            self.encrypt_password(self.default_config["sql_settings"]["mysql_password"])
        ).decode("utf-8")

        with open(CONFIGURATION_FILE_PATH, "w") as f:
            json.dump(self.default_config, f)
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Config Created!"
        )

    def add_observer(self, observer):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Adding Observer.."
        )
        self.observers.append(observer)
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Observer Added!"
        )

    def remove_observer(self, observer):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Removing Observer.."
        )
        self.observers.remove(observer)
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Observer Removed!"
        )

    def notify_observers(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Notifying Observers.."
        )
        for observer in self.observers:
            observer.notify_settings_updated()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SettingManager: Observers Notified!"
        )
