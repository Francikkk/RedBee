from datetime import datetime

# -------------------------------------------------#
#                 Shared Constants                 #
# -------------------------------------------------#
CERTIFICATE_ROOT_DIRECTORY = "./Client"
CERTIFICATE_PKI_DIRECTORY = "./Client/pki"
CERTIFICATE_TRUSTED_DIRECTORY = "./Client/pki/trusted"
CERTIFICATE_REJECTED_DIRECTORY = "./Client/pki/rejected"
CERTIFICATE_OWN_DIRECTORY = "./Client/pki/own"
OWN_CETIFICATE_DIRECTORY = "./Client/pki/own/cert"
PRIVATE_KEY_DIRECTORY = "./Client/pki/own/private"
OWN_CERTIFICATE_FILE_PATH = "./Client/pki/own/cert/cert.pem"
OWN_PRIVATE_KEY_FILE_PATH = "./Client/pki/own/private/private_key.pem"

AUTHENTICATION_DIRECTORY = "./auth"
AUTH_FILE = "./auth/auth.json"

# -------------------------------------------------#
DATA_DIRECTORY = "./Data"

CONFIGURATION_FILE_PATH = "./Data/conf.json"

KEYS_DIRECTORY = "./Data/keys"
ENCRYPTION_KEY_PATH = "./Data/keys/key_conf"

LICENSE_PUBLIC_DIRECTORY = "./Data/License"

HISTORIAN_DIRECTORY = "./Data/Historian"
HISTORIAN_CSV_FILE_PATH = "./Data/Historian/event_history.csv"
HISTORIAN_CSV_FILE_PATH_REG = r"./Data/Historian/event_history.csv"

LOGS_DIRECTORY = "./Data/Logs"
APPLICATION_LOG_PATH = f'./Data/Logs/logs_{datetime.now().strftime("%Y%m%d")}.txt'
APP_LOG_PATH_REG = r"./Data/Logs/logs.csv"

IMG_DIRECTORY = "./Data/img"
ICON_LOGO = "./Data/img/ico.png"
ICON_FULL_LOGO = "./Data/img/logo.png"
ICON_GEAR = "./Data/img/gear.png"
ICON_HISTORIAN = "./Data/img/hist_ico.png"
ICON_CSV_EXPORT = "./Data/img/export_ico.png"
ICON_CERTIFICATE = "./Data/img/cert_ico.png"
ICON_RELOAD = "./Data/img/rel_ico.png"
ICON_DIRECTORY = "./Data/img/dir_ico.png"
ICON_USER = "./Data/img/user_ico.png"
ICON_ADD_USER = "./Data/img/add_user_ico.png"
ICON_REMOVE_USER = "./Data/img/remove_user_ico.png"
ICON_ADD_ROLE = "./Data/img/add_role_ico.png"
ICON_REMOVE_ROLE = "./Data/img/remove_role_ico.png"
ICON_UNLOCK_USER = "./Data/img/unlock_ico.png"


# -------------------------------------------------#
#              Constant  Core Functions            #
# -------------------------------------------------#
# HISTORIAN_CSV_FILE_PATH

# -------------------------------------------------#
#                  Constant  Logger                #
# -------------------------------------------------#
# APPLICATION_LOG_PATH

# -------------------------------------------------#
#                  Constant Main UI                #
# -------------------------------------------------#
# OWN_CERTIFICATE_FILE_PATH
# OWN_PRIVATE_KEY_FILE_PATH
INPUT_FORM_ERROR_BACKGROUND_COLOR = (
    "QLineEdit { background-color: rgba(255, 0, 0, 0.2); }"
)
ERROR_TEXT_COLOR = "color: red"


# -------------------------------------------------#
# ICON_LOGO
# ICON_GEAR
# ICON_HISTORIAN
# HISTORIAN_CSV_FILE_PATH
# ICON_CSV_EXPORT
# ICON_CERTIFICATE
# CERTIFICATE_PKI_DIRECTORY
# OWN_CERTIFICATE_FILE_PATH
# OWN_PRIVATE_KEY_FILE_PATH
# ICON_RELOAD
# ICON_DIRECTORY
# ICON_USER
# ICON_ADD_USER
# ICON_REMOVE_USER
# ICON_ADD_ROLE
# ICON_REMOVE_ROLE
# AUTH_FILE
# ICON_FULL_LOGO
# ICON_CERTIFICATE
# ICON_HISTORIAN
# ICON_USER
# ICON_GEAR

MAIN_WINDOW_TITLE = "RedBee OPC Event Notifier"
MAIN_WINDOW_OPENING_POSITION = (100, 100)
MAIN_WINDOW_SIZE = (270, 250)
MAIN_WINDOW_BACKGROUND_COLOR = "background-color: #dff0e9;"
MAIN_WINDOW_MENU_BAR_STYLE = """
            QMenuBar {
                background-color: #dff0e9;
                color: black;
            }
            QMenuBar::item {
                background-color: #dff0e9;
                color: black;
            }
            QMenuBar::item:selected {
                background-color: #a9c5c7;
                color: black;
            }
            QMenu {
                background-color: #dff0e9;
                color: black;
                border: 1px solid black;
            }
            QMenu::item {
                background-color: #dff0e9;
                color: black;
            }
            QMenu::item:selected {
                background-color: #a9c5c7;
                color: black;
            }
        """

INFO_WINDOW_TITLE = "RedBee Info"
INFO_WINDOW_TEXT = "RedVee version:             0.9\nLicense:                         LGPL\nActivation status:          Demo\n\nFind us:                         www.RedBee.net\nContact:                        info@qberoot.com\n"
INFO_WINDOW_STYLE = """
            QLabel { color: black; }
            QMessageBox { background-color: white; }
         """

SETTING_WINDOW_TITLE = "RedBee Settings"
SETTING_WINDOW_OPENING_POSITION = (370, 100)
SETTING_WINDOW_SIZE = (425, 350)

HISTORIAN_WINDOW_TITLE = "Event Historian"
HISTORIAN_WINDOW_OPENING_POSITION = (370, 100)
HISTORIAN_WINDOW_SIZE = (1050, 600)

CERTIFICATE_HANDLER_WINDOW_TITLE = "Certificate Handler"
CERTIFICATE_HANDLER_WINDOW_OPENING_POSITION = (370, 100)
CERTIFICATE_HANDLER_WINDOW_SIZE = (425, 230)

USER_WINDOW_TITLE = "User Management"
USER_WINDOW_OPENING_POSITION = (370, 100)
USER_WINDOW_SIZE = (500, 300)

LICENSE_WINDOW_TITLE = "RedBee - License Info"
LICENSE_WINDOW_OPENING_POSITION = (100, 100)
LICENSE_WINDOW_SIZE_IF_ACTIVATED = (250, 300)
LICENSE_WINDOW_MARGINS = (10, 10, 10, 10)
LICENSE_WINDOW_SIZE_IF_NOT_ACTIVATED = (400, 120)

LICENSE_SUBSCRIPTION_LIST = ["Professional", "Enterprise"]
LICENSE_DURATION_LIST = ["1 year", "3 years", "5 years"]

LICENSE_ACTIVATION_WINDOW_TITLE = "RedBee - License Activation"
LICENSE_ACTIVATION_WINDOW_OPENING_POSITION = (100, 100)
LICENSE_ACTIVATION_WINDOW_SIZE = (400, 400)

LICENSE_UPDATE_WINDOW_TITLE = "RedBee - License Update"
LICENSE_UPDATE_WINDOW_OPENING_POSITION = (100, 100)
LICENSE_UPDATE_WINDOW_SIZE = (200, 400)

# -------------------------------------------------#
MAIN_WIDGET_TITLE = "RedBee - OPC Farm"
MAIN_WIDGET_TEXT_COLOR = "color: black;"
MAIN_WIDGET_BUTTON_CONNECT_COLOR = "background-color: #98FF98;"
MAIN_WIDGET_BUTTON_DISCONNECT_COLOR = "background-color: #FA8072;"

# -------------------------------------------------#
ROUND_INDICATOR_SIZE = (10, 10)
INFO_MESSAGE_SIZE = (200, 100)
INFO_MESSAGE_POSITION = (300, 300)


# -------------------------------------------------#
#            Constant Certificate Handler          #
# -------------------------------------------------#
# OWN_CERTIFICATE_FILE_PATH
# OWN_PRIVATE_KEY_FILE_PATH
# ICON_CERTIFICATE
CERTIFICATE_NAME = "RedBee"

# -------------------------------------------------#
#                Constant Info Manager             #
# -------------------------------------------------#
# OWN_CETIFICATE_DIRECTORY
# PRIVATE_KEY_DIRECTORY
# HISTORIAN_DIRECTORY
# LOGS_DIRECTORY
# IMG_DIRECTORY
# KEYS_DIRECTORY
# APPLICATION_LOG_PATH
# HISTORIAN_CSV_FILE_PATH_REG
# APP_LOG_PATH_REG
CERTIFICATES_DIRECTORIES = [
    CERTIFICATE_ROOT_DIRECTORY,
    CERTIFICATE_PKI_DIRECTORY,
    CERTIFICATE_OWN_DIRECTORY,
    CERTIFICATE_TRUSTED_DIRECTORY,
    CERTIFICATE_REJECTED_DIRECTORY,
    PRIVATE_KEY_DIRECTORY,
    OWN_CETIFICATE_DIRECTORY,
]
DATA_DIRECTORIES = [
    DATA_DIRECTORY,
    HISTORIAN_DIRECTORY,
    LOGS_DIRECTORY,
    IMG_DIRECTORY,
    KEYS_DIRECTORY,
    LICENSE_PUBLIC_DIRECTORY
]

# -------------------------------------------------#
#             Constant Setting Manager             #
# -------------------------------------------------#
# ENCRYPTION_KEY_PATH
# CONFIGURATION_FILE_PATH
INITIAL_CONFIGURATION = {
    "general_settings": {
        "authentication": False,
        "lock_timer": False,
        "lock_timer_value": "30 minutes",
        "auto_connect": False,
        "dark_theme": True,
        "language": "English",
    },
    "opc_settings": {
        "host": "localhost",
        "port": "4840",
        "security_mode": "None",
        "security_policy": "None",
        "anonymous": True,
        "username": "",
        "password": "",
    },
    "alarm_subscription": {
        "notification_threshold_lower": "600",
        "notification_threshold_upper": "1000",
    },
    "twilio_settings": {
        "twilio_enabled": False,
        "twilio_sid": "",
        "twilio_auth_token": "",
        "twilio_number": "+39123456789",
        "receiver_number": "+49987654321",
    },
    "smtp_settings": {
        "mail_enabled": False,
        "mail_server_address": "smtp.example.com",
        "port_mail": "587",
        "ssl_enabled": True,
        "sender_mail": "sender@example.com",
        "sender_password": "",
        "receiver_mail": "receiver@example.com",
    },
    "sql_settings": {
        "sql_enabled": False,
        "mssql_enabled": False,
        "mssql_server_address": "localhost",
        "mssql_port": "1433",
        "mssql_database_name": "database",
        "mssql_username": "",
        "mssql_password": "",
        "mysql_enabled": False,
        "mysql_server_address": "localhost",
        "mysql_port": "3306",
        "mysql_database_name": "database",
        "mysql_username": "",
        "mysql_password": "",
    },
}


# -------------------------------------------------#
#           Constant Authentication Manager        #
# -------------------------------------------------#
# AUTHENTICATION_DIRECTORY = './auth'
# ENCRYPTION_KEY_PATH = './Data/keys/key_conf'
# AUTH_FILE
# ICON_USER
# ICON_UNLOCK_USER
PRIVILEGES_LIST = [
    "Start",
    "Stop",
    "Save configuration",
    "Load configuration",
    "General",
    "OPC",
    "Alarm",
    "Twilio",
    "SMTP",
    "View user window",
    "Add user",
    "Edit user",
    "Remove user",
    "Add role",
    "Edit role",
    "Remove role",
    "View certificate window",
    "Regenerate certificate",
    "Open certificate location",
    "View alarm log window",
    "Export alarm log",
]
INITIAL_USERS = {
    "admin": {"role": "Administrator", "password": "Pa55word", "domain": "RedBee"},
    "user": {"role": "Operator", "password": "Pa55word", "domain": "RedBee"},
}
INITIAL_ROLES = {
    "Administrator": {
        "Main": ["Start", "Stop", "Save configuration", "Load configuration"],
        "Settings": ["General", "OPC", "Alarm", "Twilio", "SMTP"],
        "User_manager": [
            "View user window",
            "Add user",
            "Edit user",
            "Remove user",
            "Add role",
            "Edit role",
            "Remove role",
        ],
        "Certificate": [
            "View certificate window",
            "Regenerate certificate",
            "Open certificate location",
        ],
        "Alarm Log": ["View alarm log window", "Export alarm log"],
    },
    "Operator": {
        "Main": ["Start"],
        "Settings": [],
        "User_manager": [],
        "Certificate": [],
        "Alarm Log": ["View alarm log window"],
    },
}

# -------------------------------------------------#
LOGIN_DIALOG_TITLE = "Login"

USER_MANAGER_REMOVE_TITLE = "Remove User"
USER_MANAGER_ADD_TITLE = "Add User"
USER_MANAGER_INITIAL_POSITION = (800, 100)
USER_MANAGER_REMOVE_SIZE = (300, 150)
USER_MANAGER_ADD_SIZE = (300, 200)
USER_MANAGER_APPLICATION_DOMAIN = "RedBee"

ROLE_MANAGER_REMOVE_TITLE = "Remove Role"
ROLE_MANAGER_ADD_TITLE = "Add Role"
ROLE_MANAGER_INITIAL_POSITION = (900, 100)
ROLE_MANAGER_REMOVE_SIZE = (300, 150)
ROLE_MANAGER_ADD_SIZE = (300, 600)
ROLE_MANAGER_EMPTY_PERMISSIONS_CATEGORY = {
    "Main": [],
    "Settings": [],
    "User_manager": [],
    "Certificate": [],
    "Alarm Log": [],
}

UNLOCK_USER_DIALOG_TITLE = "Unlock User"


# -------------------------------------------------#
#                 License Manager                  #
# -------------------------------------------------#
# LICENSE_PUBLIC_DIRECTORY
LICENSE_PUBLIC_FILE = "./Data/License/lic.json"
LICENSE_PRIVATE_DIRECTORY = "./Lic"
LICENSE_PRIVATE_FILE = "./Lic/license_info.json"
ENCRYPT_KEY_LICENSE = "./Data/keys/key_lic"