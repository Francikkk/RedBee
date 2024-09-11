# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
import datetime
from PySide6.QtWidgets import QMessageBox


# --------------------Messages---------------------#
# Exception handling UI and logging exceptions
class ExceptionHandler:
    def __init__(self):
        pass

    @staticmethod
    def handle_exception(
        error_message,
        class_name="",
        title="Error",
        icon=QMessageBox.Critical,
        buttons=QMessageBox.Ok,
        width=200,
        height=100,
    ):
        ExceptionHandler.log_exception(error_message, class_name)
        error_box = QMessageBox()
        error_box.setWindowTitle(title)
        error_box.setIcon(icon)
        error_box.setStandardButtons(buttons)
        error_box.setDefaultButton(QMessageBox.Ok)
        error_box.setText(f"An error occurred in {class_name}")
        error_box.setInformativeText(error_message)
        error_box.setGeometry(300, 300, width, height)
        error_box.setFixedSize(width, height)
        error_box.exec()

    @staticmethod
    def unhandled_exception(exception, class_name=""):
        error_message = f"Unhandled Exception: {exception}"
        ExceptionHandler.log_exception(error_message, class_name)
        error_box = QMessageBox()
        error_box.setWindowTitle("UnhandledException")
        error_box.setIcon(QMessageBox.Critical)
        error_box.setStandardButtons(QMessageBox.Ok)
        error_box.setDefaultButton(QMessageBox.Ok)
        error_box.setInformativeText(f"An error occurred in {class_name}")
        error_box.setText(error_message)
        error_box.exec()

    @staticmethod
    def log_exception(error_message, class_name=""):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | {class_name}: **EXCEPTION**"
        )
        print(str(error_message))
        print("#######################################################")