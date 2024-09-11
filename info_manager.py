# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from certificate_handler import CertificateHandler
from setting_manager import SettingManager
from license_manager import LicenseManager
from constants import (
    CERTIFICATES_DIRECTORIES,
    OWN_CETIFICATE_DIRECTORY,
    PRIVATE_KEY_DIRECTORY,
    DATA_DIRECTORIES,
    HISTORIAN_DIRECTORY,
    LOGS_DIRECTORY,
    IMG_DIRECTORY,
    KEYS_DIRECTORY,
    HISTORIAN_CSV_FILE_PATH_REG,
    APP_LOG_PATH_REG,
    LICENSE_PUBLIC_DIRECTORY
)

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
import pandas as pd
import datetime
import os


# Create the needed directory (./Data, ./Client) and subdirectories. Create a configuration file with default values. Initialize the certificate handler
class InfoManager:
    """
    InfoManager

    Description:
    The InfoManager class is responsible for managing data-related tasks such as creating necessary directories,
    initializing the certificate handler, and managing configuration settings.

    Responsibilities:
    Create required directories for storing data and certificates.
    Initialize the certificate handler.
    Create and manage configuration settings.

    Attributes:
    csv_handler: Instance of the CSVHandler class.
    setting_manager: Instance of the SettingManager class.
    cert_handler: Instance of the CertificateHandler class.

    Interfaces:
    create_cert_directory(): Creates necessary directories for storing certificates.
    create_data_directory(): Creates necessary directories for storing data.
    initialize(): Initializes the data manager, creating directories and initializing the certificate handler.
    """

    def __init__(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | InfoManager: initializing.."
        )
        self.create_cert_directory()
        self.create_data_directory()
        self.license_manager = LicenseManager()
        self.csv_handler = CSVHandler()
        self.cert_handler = CertificateHandler()
        self.setting_manager = SettingManager()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | InfoManager: Initialized!"
        )

    def create_cert_directory(self):
        if (not os.path.exists(PRIVATE_KEY_DIRECTORY)) or (
            not os.path.exists(OWN_CETIFICATE_DIRECTORY)
        ):
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | InfoManager: Creating certificate directories.."
            )
            # Create directories if they don't exist
            for directory in CERTIFICATES_DIRECTORIES:
                os.makedirs(directory, exist_ok=True)
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | InfoManager: Certificate directories created!"
            )

    def create_data_directory(self):
        if (
            (not os.path.exists(HISTORIAN_DIRECTORY))
            or (not os.path.exists(LOGS_DIRECTORY))
            or (not os.path.exists(IMG_DIRECTORY))
            or (not os.path.exists(KEYS_DIRECTORY))
            or  (not os.path.exists(LICENSE_PUBLIC_DIRECTORY))
        ):
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | InfoManager: Creating data directories.."
            )
            # Create directories if they don't exist
            for directory in DATA_DIRECTORIES:
                os.makedirs(directory, exist_ok=True)
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | InfoManager: Data directories created!"
            )


# CSV Handling for storing historian data, exception logs, and regular logs
class CSVHandler:
    """
    CSVHandler
    Description:
    The CSVHandler class manages CSV file operations for storing historian data, exception logs, and regular logs.

    Responsibilities:
    Save and load data to/from CSV files.
    Manage historian, exception log, and regular log data.

    Attributes:
    historian: Dataframe for historian records.
    exception_log: Dataframe for exception logs.
    logs: Dataframe for regular logs.
    historian_path: Path to the historian CSV file.
    exception_log_path: Path to the exception log CSV file.
    logs_path: Path to the regular log CSV file.

    Interfaces:
    save_to_csv(df, path): Saves a dataframe to the specified CSV file path.
    load_from_csv(path): Loads data from the specified CSV file path.
    Methods for saving and loading historian, exception log, and regular log data to/from CSV files.
    """

    def __init__(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: initializing.."
        )
        self.historian = pd.DataFrame()
        self.logs = pd.DataFrame()
        self.historian_path = HISTORIAN_CSV_FILE_PATH_REG
        self.logs_path = APP_LOG_PATH_REG
        self.historian_load_from_csv()
        self.logs_load_from_csv()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Created!"
        )

    def save_to_csv(self, df, path):
        if path == self.historian_path:
            self.historian_save_to_csv(df)
        elif path == self.logs_path:
            self.logs_save_to_csv(df)
        else:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Invalid path!"
            )

    def load_from_csv(self, path):
        if os.path.exists(path):
            if path == self.historian_path:
                self.historian_load_from_csv()
            elif path == self.logs_path:
                self.logs_load_from_csv()
            else:
                print(
                    f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Invalid path!"
                )

    def historian_save_to_csv(self, df):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Saving historian to CSV.."
        )
        self.historian = pd.concat([self.historian, df], ignore_index=True)
        self.historian.to_csv(self.historian_path, sep=";", index=False)
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Saved historian to CSV!"
        )

    def historian_load_from_csv(self):
        if os.path.exists(self.historian_path):
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Loading historian from CSV.."
            )
            self.historian = pd.read_csv(self.historian_path, sep=";")
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Loaded historian from CSV!"
            )

    def logs_save_to_csv(self, df):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Saving logs to CSV.."
        )
        self.logs = pd.concat([self.logs, df], ignore_index=True)
        self.logs.to_csv(self.logs_path, index=False)
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Saved logs to CSV!"
        )

    def logs_load_from_csv(self):
        if os.path.exists(self.logs_path):
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Loading logs from CSV.."
            )
            self.logs = pd.read_csv(self.logs_path)
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CSVHandler: Loaded logs from CSV!"
            )
