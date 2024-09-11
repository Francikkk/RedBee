# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from constants import APPLICATION_LOG_PATH

# -------------------------------------------------#
#                  Library Import                  #
# -------------------------------------------------#
import os
import sys


# ------------------InfoManagement-----------------#
# Logger class to redirect stdout and stderr to a log file
class Logger:
    """
    Logger
    Description:
    The Logger class redirects stdout and stderr to a log file for logging application output.

    Responsibilities:
    Redirect stdout and stderr to a log file.
    Close the log file.

    Attributes:
    log_path: Path to the log file.

    Interfaces:
    init_log(): Initializes the log file by redirecting stdout and stderr.
    close_log(): Closes the log file.
    """

    def __init__(self):
        self.log_path = APPLICATION_LOG_PATH
        self.init_log()

    def init_log(self):
        if not os.path.exists(self.log_path):
            open(self.log_path, "w").close()
        sys.stdout = open(self.log_path, "a")
        sys.stderr = open(self.log_path, "a")

    def close_log(self):
        sys.stdout.close()
        sys.stderr = sys.__stderr__