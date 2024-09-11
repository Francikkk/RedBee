# -------------------------------------------------#
#                Versions History                  #
# -------------------------------------------------#
# Version: 0.10 -> OPC Connection, basic event
#                  handling
# Version: 0.20 -> Data logging in dataframe
#                  and .csv historical events
# Version: 0.30 -> SMS Sending by Twilio API
# Version: 0.35 -> Email sending with SMTP
# Version: 0.40 -> basic user interface with terminal
# Version: 0.50 -> User authentication for OPC
#                  connection
# Version: 0.55 -> Security mode and security
#                  policy option for OPC UA
#                  connection, certificate
#                  management
# Version: 0.60 -> User interface with PySide6,
#                  connection, settings and
#                  configuration
# Version: 0.65 -> Exception handling and logging
#                  (UI), UI certificate
#                  management
# Version: 0.69 -> Encyption of configuration password
#
# Upcoming Versions:
#
# Version: 0.70 -> Data logging in SQL database
#                  (MySQL, MSSQL)
# Version: 0.80 -> Multiple configurations
# Version: 0.90 -> Security, encryption of
#                  pasword, app authentication
#                  and hashing
#
# -------------------------------------------------#
#                    Upcoming                      #
# -------------------------------------------------#
#
# Connecting to MySQL (DONE)
# Connecting MSSQL
# Data import in SQL db
# Data logging in SQL db
# Data export from SQL db
#
# -------------------------------------------------#
#                    Bugs List                     #
# -------------------------------------------------#
#
#
# -------------------------------------------------#
#                   Description                    #
# -------------------------------------------------#
# RedBee OPC Event Notifier is a software that     #
# connects to an OPC UA server, subscribes to      #
# events and notifies the user via SMS and email.  #
# It support OPC UA connection with user           #
# authentication and security mode and policy.     #
# It's composed by a user interface, a data        #
# manager and a OPC UA client.                     #
#                                                  #
# The user interface is created with PyQt5 and     #
# allows the user to configure the OPC UA          #
# connection, the alarm subscription, the Twilio   #
# and SMTP settings.                               #
#                                                  #
# The data manager creates the needed directories  #
# and files, manages the settings and the          #
# certificate.                                     #
#                                                  #
# The OPC UA client connects to the server,        #
# subscribes to events and logs them in a CSV      #
# file.                                            #
# The OPC UA client is uses a handler              #
# that manages the events and notifies the user.   #
# The handler sends SMS and email to the user,     #
# it also logs the events in a CSV file.           #
# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from logger import Logger
from exception_handler import ExceptionHandler
from info_manager import InfoManager
from main_ui import MainUI, InfoMessage
from core_functions import OpcUaClient, SubHandler, SmsSender, MailSender
from constants import ICON_LOGO

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
import datetime
import sys
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtGui import QIcon



# ---------------------Core------------------------#
# Main class to start the application
class Core:
    """
    Core

    Description:
    The Core class is the main class responsible for initializing the application, managing the data manager, certificate handler, setting manager, OPC UA client, and other components.

    Responsibilities:
    Initialize various components of the application.
    Manage connections to the OPC UA server.
    Handle settings updates and notify observers.

    Attributes:
    info_manager: Instance of the InfoManager class.
    certificate_handler: Instance of the CertificateHandler class.
    setting_manager: Instance of the SettingManager class.
    csv_handler: Instance of the CSVHandler class.
    opcua_client: OPC UA client for communication with the OPC server.
    alarm_handler: Instance of the SubHandler class for handling alarms.
    sms_sender: Instance of the SmsSender class for sending SMS notifications.
    mail_sender: Instance of the MailSender class for sending email notifications.

    Interfaces:
    main(): Initializes the user interface and starts the application.
    notify_settings_updated(): Notifies observers of settings updates.
    update_settings(): Updates application settings.
    connect_opcua(): Connects to the OPC UA server.
    disconnect_opcua(): Disconnects from the OPC UA server.
    """

    def __init__(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Core initializing.."
        )
        self.info_manager = InfoManager()
        self.certificate_handler = self.info_manager.cert_handler
        self.setting_manager = self.info_manager.setting_manager
        self.setting_manager.add_observer(self)
        self.update_settings()
        self.csv_handler = self.info_manager.csv_handler
        self.auth_handler = self.info_manager.setting_manager.auth_handler
        self.opcua_client = None
        self.alarm_handler = None
        self.sms_sender = None
        self.mail_sender = None

        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Core initialized!"
        )

    def main(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Initializing UI.."
        )
        try:
            app = QApplication.instance()
            if not app:
                app = QApplication(sys.argv)
            app.setStyle("Fusion")
            app_icon = QIcon(ICON_LOGO)
            app.setWindowIcon(app_icon)
            self.main_window = MainUI(core)
            self.main_window.setWindowIcon(app_icon)
            self.main_window.show()
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e), "UI", "Error", QMessageBox.Critical, QMessageBox.Ok, 200, 100
            )
        else:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: UI MainUI created!"
            )
            if self.setting_manager.general_settings["auto_connect"]:
                try:
                    self.connect_opcua()
                except Exception as e:
                    ExceptionHandler.handle_exception(
                        str(e),
                        "Core",
                        "Error",
                        QMessageBox.Critical,
                        QMessageBox.Ok,
                        200,
                        100,
                    )
            sys.exit(app.exec())
            if self.opcua_client != None:
                self.disconnect_opcua()

    def notify_settings_updated(self):
        self.update_settings()
        if self.opcua_client:
            try:
                self.disconnect_opcua()
            except Exception as e:
                ExceptionHandler.handle_exception(
                    str(e),
                    "Core",
                    "Error",
                    QMessageBox.Critical,
                    QMessageBox.Ok,
                    200,
                    100,
                )
            else:
                try:
                    self.connect_opcua()
                except Exception as e:
                    ExceptionHandler.handle_exception(
                        str(e),
                        "Core",
                        "Error",
                        QMessageBox.Critical,
                        QMessageBox.Ok,
                        200,
                        100,
                    )

    def update_settings(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Updating Settings.."
        )
        try:
            self.opc_settings = self.setting_manager.opc_settings
            self.alarm_subscription = self.setting_manager.alarm_subscription
            self.twilio_settings = self.setting_manager.twilio_settings
            self.smtp_settings = self.setting_manager.smtp_settings
            # SQL settings
        except Exception as e:
            ExceptionHandler.handle_exception(
                str(e),
                self.setting_manager.__class__.__name__,
                "Error",
                QMessageBox.Critical,
                QMessageBox.Ok,
                200,
                100,
            )
        else:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Settings Updated!"
            )
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Current settings:{self.opc_settings} {self.alarm_subscription} {self.twilio_settings} {self.smtp_settings}"
            )

    def connect_opcua(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Initializing objects for connection to opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}.."
        )
        self.main_window.main_widget.update_indicator("yellow")
        self.update_settings()
        self.opcua_client = OpcUaClient(
            self.opc_settings["host"],
            self.opc_settings["port"],
            self.opc_settings["security_mode"],
            self.opc_settings["security_policy"],
            self.opc_settings["username"],
            self.opc_settings["password"],
            self.certificate_handler,
        )
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: OPC UA client initialized!"
        )
        if self.setting_manager.twilio_settings["twilio_enabled"]:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Creating SMS sender.."
            )
            self.sms_sender = SmsSender(
                self.setting_manager.twilio_settings["twilio_sid"],
                self.setting_manager.twilio_settings["twilio_auth_token"],
                self.setting_manager.twilio_settings["twilio_number"],
                self.setting_manager.twilio_settings["receiver_number"],
            )
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: SMS sender created!"
            )
        else:
            self.sms_sender = None
        if self.setting_manager.smtp_settings["mail_enabled"]:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Creating Mail sender.."
            )
            self.mail_sender = MailSender(
                self.setting_manager.smtp_settings["mail_server_address"],
                self.setting_manager.smtp_settings["port_mail"],
                self.setting_manager.smtp_settings["ssl_enabled"],
                self.setting_manager.smtp_settings["sender_mail"],
                self.setting_manager.smtp_settings["sender_password"],
                self.setting_manager.smtp_settings["receiver_mail"],
            )
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Mail sender created!"
            )
        else:
            self.mail_sender = None
        self.alarm_handler = SubHandler(
            self.setting_manager.alarm_subscription["notification_threshold_lower"],
            self.setting_manager.alarm_subscription["notification_threshold_upper"],
            self.csv_handler,
            self.sms_sender,
            self.mail_sender,
        )
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Alarm handler created!"
        )
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Objects initialized!"
        )
        try:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Connecting to OPC UA server opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}.."
            )
            self.opcua_client.connect()
        except Exception as e:
            if str(e) == "":
                e = f"Connection error!\nAttempt to connect to ocp.tcp://{self.opc_settings['host']}:{self.opc_settings['port']} failed!\nTry:\n1. Check if the server is running.\n2. Try to ping the OPC UA server\n3. Check if the security and authentication options are correct.\n4. Check if the certificate has been properly trusted"
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Connection error - {str(e)}"
            )
            self.main_window.main_widget.update_indicator("red")
            ExceptionHandler.handle_exception(
                str(e),
                self.opcua_client.__class__.__name__,
                "Error",
                QMessageBox.Critical,
                QMessageBox.Ok,
                200,
                100,
            )
            self.opcua_client = None
            self.alarm_handler = None
            self.sms_sender = None
            self.mail_sender = None
        else:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Connected to opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}"
            )
            try:
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Subscribing to events.."
                )
                self.opcua_client.get_events(self.alarm_handler)
            except Exception as e:
                self.main_window.main_widget.update_indicator("red")
                ExceptionHandler.handle_exception(
                    str(e),
                    self.opcua_client.__class__.__name__,
                    "Error",
                    QMessageBox.Critical,
                    QMessageBox.Ok,
                    200,
                    100,
                )
                self.opcua_client = None
                self.alarm_handler = None
                self.sms_sender = None
                self.mail_sender = None
            else:
                self.main_window.main_widget.update_indicator("green")
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Subscribed to events!"
                )
                InfoMessage.show_info_message(
                    f"CORE: Connected to OPC UA server!\nHost: opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}"
                )

    def disconnect_opcua(self):
        self.main_window.main_widget.update_indicator("yellow")
        if self.opcua_client != None:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Disconnecting from OPC UA server opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}.."
            )
            try:
                self.opcua_client.disconnect()
            except Exception as e:
                self.main_window.main_widget.update_indicator("red")
                ExceptionHandler.handle_exception(
                    str(e),
                    self.opcua_client.__class__.__name__,
                    "Error",
                    QMessageBox.Critical,
                    QMessageBox.Ok,
                    200,
                    100,
                )
                self.opcua_client = None
                self.alarm_handler = None
                self.sms_sender = None
                self.mail_sender = None
            else:
                self.opcua_client = None
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Disconnected from OPC UA server opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}"
                )
                self.alarm_handler = None
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Alarm handler deleted!"
                )
                self.sms_sender = None
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: SMS sender deleted!"
                )
                self.mail_sender = None
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: Mail sender deleted!"
                )
                self.main_window.main_widget.update_indicator("red")
                InfoMessage.show_info_message(
                    f"CORE: Disconnected from OPC UA server!\n Host: opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}"
                )
                InfoMessage.show_info_message(
                    f"CORE: Disconnected from OPC UA server!\n Host: opc.tcp://{self.opc_settings['host']}:{self.opc_settings['port']}"
                )
        else:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CORE: No OPC connection to disconnect!"
            )
            self.main_window.main_widget.update_indicator("red")
            InfoMessage.show_info_message("CORE: No OPC connection to disconnect!")


# ---------------------Main------------------------#
if __name__ == "__main__":
    sys.excepthook = ExceptionHandler.unhandled_exception
    logger = Logger()
    core = Core()
    core.main()
    logger.close_log()
