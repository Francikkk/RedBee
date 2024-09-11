# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from constants import HISTORIAN_CSV_FILE_PATH

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
from opcua import Client
from twilio.rest import Client as TwilioClient
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pyodbc
import pandas as pd
import datetime


# -------------------------------------------------#
#                      Model                       #
# -------------------------------------------------#
# --------------------Function---------------------#
# Manage the OPC UA connection and events subscription
class OpcUaClient:
    def __init__(
        self,
        host,
        port,
        security_mode,
        security_policy,
        username,
        password,
        certificate_handler,
    ):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Initializing.."
        )
        self.host = host
        self.port = port
        self.server_url = f"opc.tcp://{host}:{port}"
        self.client = Client(self.server_url)
        self.security_mode = security_mode
        self.security_policy = security_policy
        self.username = username
        self.password = password
        self.certificate_handler = certificate_handler
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Created!"
        )

    def connect(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Connecting.."
        )
        if self.username and self.password:
            self.client.set_user(self.username)
            self.client.set_password(self.password)
        if self.security_mode != "None":
            self.client.set_security_string(
                f"{self.security_policy},{self.security_mode},{self.certificate_handler.cert_path},{self.certificate_handler.private_key_path}"
            )
            # self.client.connect()
        try:
            self.client.connect()
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Connected to opc.tcp://{self.host}:{self.port}!"
            )
        except Exception as e:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Connection error - {e}"
            )
            # ExceptionHandler.handle_exception(str(e), 'OpcUaClient', 'Error', QMessageBox.Critical)
            raise Exception(e)

    def disconnect(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Disconnecting.."
        )
        self.client.disconnect()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Disconnected!"
        )

    def get_events(self, handler):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Subscribing to events.."
        )
        self.subscription = self.client.create_subscription(500, handler)
        self.subscription.subscribe_events()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | OpcUaClient: Subscribed to events!"
        )


# Manage the handling of events, notification, save on .csv
class SubHandler:
    def __init__(
        self,
        notification_threshold_lower,
        notification_threshold_upper,
        csv_handler,
        sms_sender=None,
        mail_sender=None,
    ):
        self.historian_path = HISTORIAN_CSV_FILE_PATH
        self.notification_threshold_lower = notification_threshold_lower
        self.notification_threshold_upper = notification_threshold_upper
        self.csv_handler = csv_handler
        self.sms_sender = sms_sender
        self.mail_sender = mail_sender
        self.df_historical_events = pd.DataFrame(
            columns=[
                "Node",
                "EventTime",
                "Severity",
                "SourceName",
                "Message",
                "SourceNode",
                "Type",
                "ID",
            ]
        )

    def data_change(self, node, val, data):
        print("Data Change Detected", node, val)

    def event(self, node, val):
        event_data = {
            "Node": node,
            "EventTime": val.Time,
            "Severity": val.Severity,
            "SourceName": val.SourceName,
            "Message": val.Message.Text,
            "SourceNode": val.SourceNode,
            "Type": val.EventType,
            "ID": val.EventId,
        }
        event_df = pd.DataFrame([event_data])
        self.df_historical_events = pd.concat(
            [self.df_historical_events, event_df], ignore_index=True
        )
        print(self.df_historical_events)
        self.csv_handler.save_to_csv(self.df_historical_events, self.historian_path)
        # # Diagnostic prints
        # print(f"#################################################")
        # print(f"Event Detected: \nNode: {node}\nValue: {val}")
        # print(f"#################################################\n")
        # print(val.Message.Text)
        # print(val.Severity)
        # print(val.SourceName)
        # print(type(val.Message))
        # print(self.df_historical_events)
        if (
            int(self.notification_threshold_lower)
            <= val.Severity
            <= int(self.notification_threshold_upper)
        ):
            self.notify(val)

    def notify(self, event_val):
        message = f"Event Severity: {event_val.Severity}\nSource Name: {event_val.SourceName}\nMessage: {event_val.Message.Text}"
        # Sending SMS
        if self.sms_sender:
            self.sms_sender.send_sms(
                message
            )  # Uncomment this line to send SMS, once recharge the credit
        # Sending Email
        if self.mail_sender:
            self.mail_sender.send_mail("Event Notification", message)


# Manage the sending of SMS by Twilio API
class SmsSender:
    def __init__(self, account_sid, auth_token, from_number, to_number):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SmsSender: initializing.."
        )
        self.twilio_client = TwilioClient(account_sid, auth_token)
        self.from_number = from_number
        self.to_number = to_number
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SmsSender: created!"
        )

    def send_sms(self, message):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SmsSender: Sending SMS.."
        )
        self.twilio_client.messages.create(
            body=message, from_=self.from_number, to=self.to_number
        )
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SmsSender: SMS sent!"
        )


# Manage the sending of emails by SMTP
class MailSender:
    def __init__(
        self,
        mail_server_address,
        port,
        ssl_enabled,
        sender_mail,
        sender_password,
        receiver_mail,
    ):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MailSender: initializing.."
        )
        self.mail_server_address = mail_server_address
        self.port = port
        self.ssl_enabled = ssl_enabled
        self.sender_mail = sender_mail
        self.sender_password = sender_password
        self.receiver_mail = receiver_mail
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MailSender: created!"
        )

    def send_mail(self, subject, body):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MailSender: Sending mail.."
        )
        msg = MIMEMultipart()
        msg["From"] = self.sender_mail
        msg["To"] = self.receiver_mail
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(self.mail_server_address, self.port)
        if self.ssl_enabled:
            server.starttls()
        server.login(self.sender_mail, self.sender_password)
        text = msg.as_string()
        server.sendmail(self.sender_mail, self.receiver_mail, text)
        server.quit()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | MailSender: Mail sent!"
        )


# Manage the SQL Connection and logging
class SqlHandler:
    def __init__(self, server_address, port, database_name, username, password):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Initializing.."
        )
        self.server_address = server_address
        self.port = port
        self.database_name = database_name
        self.username = username
        self.password = password
        self.connection_mssql = None
        self.cursor_mssql = None
        self.connection_mysql = None
        self.cursor_mysql = None
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Created!"
        )

    def connect_to_mssql(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Connecting to MSSQL Server.."
        )
        try:
            self.connection_mssql = pyodbc.connect(
                f"DRIVER=ODBC Driver 17 for SQL Server;SERVER={self.server_address};DATABASE={self.database_name};UID={self.username};PWD={self.password}"
            )
            self.cursor_mssql = self.connection_mssql.cursor()
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Connected to {self.server_address},{self.port}!"
            )
        except Exception as e:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Connection error - {e}"
            )
            raise Exception(e)

    def disconnect_from_mssql(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Disconnecting.."
        )
        self.connection_mssql.close()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Disconnected!"
        )

    def connect_to_mysql(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Connecting to MySQL Server.."
        )
        try:
            self.connection_mysql = pyodbc.connect(
                f"DRIVER=MySQL ODBC 8.0 Unicode Driver;SERVER={self.server_address};DATABASE={self.database_name};UID={self.username};PWD={self.password}"
            )  # ;PORT={self.port}")
            self.cursor_mysql = self.connection_mysql.cursor()
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Connected to {self.server_address}!"
            )
        except Exception as e:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Connection error - {e}"
            )
            raise Exception(e)

    def disconnect_from_mysql(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Disconnecting.."
        )
        self.connection_mysql.close()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Disconnected!"
        )

    def log_event_mssql(self, event_data):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Logging event.."
        )
        try:
            self.cursor_mssql.execute(
                "INSERT INTO EventLog (Node, EventTime, Severity, SourceName, Message, SourceNode, Type, ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                event_data["Node"],
                event_data["EventTime"],
                event_data["Severity"],
                event_data["SourceName"],
                event_data["Message"],
                event_data["SourceNode"],
                event_data["Type"],
                event_data["ID"],
            )
            self.connection_mssql.commit()
        except Exception as e:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Logging error - {e}"
            )
            raise Exception(e)

    def log_event_mysql(self, event_data):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Logging event.."
        )
        try:
            self.cursor_mysql.execute(
                "INSERT INTO EventLog (Node, EventTime, Severity, SourceName, Message, SourceNode, Type, ID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    event_data["Node"],
                    event_data["EventTime"],
                    event_data["Severity"],
                    event_data["SourceName"],
                    event_data["Message"],
                    event_data["SourceNode"],
                    event_data["Type"],
                    event_data["ID"],
                ),
            )
            self.connection_mysql.commit()
        except Exception as e:
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | SqlHandler: Logging error - {e}"
            )
            raise Exception(e)
