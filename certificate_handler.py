# -------------------------------------------------#
#                  Module Import                   #
# -------------------------------------------------#
from exception_handler import ExceptionHandler
from constants import (
    OWN_CERTIFICATE_FILE_PATH,
    OWN_PRIVATE_KEY_FILE_PATH,
    ICON_CERTIFICATE,
    CERTIFICATE_NAME,
)

# -------------------------------------------------#
#                 Library Import                  #
# -------------------------------------------------#
import datetime
import os
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QDialog,
)
from PySide6.QtGui import QIcon


# Manage the certificate, check if a RedBee certificate is present, if not generate a new one
class CertificateHandler:
    """
    CertificateHandler

    Description:
    The CertificateHandler class is responsible for managing the certificate used by the application.
    It checks if a RedBee certificate is present, and if not, it generates a new one.

    Responsibilities:
    Generate a RedBee certificate if one does not exist.
    Load the existing certificate and private key.
    Provide methods for certificate generation and initialization.
    Provide a user interface for entering the organization name for certificate generation.

    Attributes:
    cert_path: Path to the certificate file.
    private_key_path: Path to the private key file.
    certificate: Stores the certificate data.
    private_key: Stores the private key data.

    Interfaces:
    generate_certificate(organization): Generates a RedBee certificate with the specified organization name.
    initialize(): Initializes the certificate handler, loading the certificate and private key if they exist.
    cert_param_ui(): Provides a user interface for entering the organization name for certificate generation.
    """

    def __init__(self):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Initializing.."
        )
        self.cert_path = OWN_CERTIFICATE_FILE_PATH
        self.private_key_path = OWN_PRIVATE_KEY_FILE_PATH
        self.certificate = ""
        self.private_key = ""
        self.initialize()
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Initialized!"
        )

    def generate_certificate(self, name="", organization="", country="", locality=""):
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Generating Certificate.."
        )
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Create a certificate
        subject_name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
        issuer_name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
        if organization:
            subject_name_attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
            )
            issuer_name_attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
            )
        if country:
            subject_name_attributes.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, country)
            )
            issuer_name_attributes.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, country)
            )
        if locality:
            subject_name_attributes.append(
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality)
            )
            issuer_name_attributes.append(
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality)
            )

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(subject_name_attributes))
        builder = builder.issuer_name(x509.Name(issuer_name_attributes))

        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Add the dataEncipherment extension
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        # Serialize certificate and private key
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write certificate in ./Client/pki/own/cert/certificate.pem
        with open(OWN_CERTIFICATE_FILE_PATH, "wb") as f:
            f.write(cert_pem)
        self.cert_path = OWN_CERTIFICATE_FILE_PATH
        # Write private key in ./Client/pki/own/private/private_key.pem
        with open(OWN_PRIVATE_KEY_FILE_PATH, "wb") as f:
            f.write(private_key_pem)
        self.private_key_path = OWN_PRIVATE_KEY_FILE_PATH
        print(
            f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Certificate and private key generated!"
        )
        # return cert_pem, private_key_pem
        return certificate, private_key

    def initialize(self):
        if (not os.path.exists(OWN_PRIVATE_KEY_FILE_PATH)) or (
            not os.path.exists(OWN_CERTIFICATE_FILE_PATH)
        ):
            try:
                name, organization, country, locality = (
                    CertificateHandler.cert_param_ui()
                )
            except Exception as e:
                pass
            else:
                self.certificate, self.private_key = self.generate_certificate(
                    name, organization, country, locality
                )
        else:
            with open(self.cert_path, "rb") as f:
                self.certificate = x509.load_pem_x509_certificate(f.read())
            with open(self.private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            print(
                f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Certificate and private key loaded!"
            )

    def regenerate(self):
        try:
            name, organization, country, locality = CertificateHandler.cert_param_ui()
        except Exception as e:
            pass
        else:
            if not name and not organization and not country and not locality:
                pass
            else:
                self.certificate, self.private_key = self.generate_certificate(
                    name, organization, country, locality
                )

    @staticmethod
    def cert_param_ui():
        name, organization, country, locality = "", "", "", ""
        try:
            cert_app = QApplication.instance()
            if not cert_app:
                cert_app = QApplication(sys.argv)
            dialog = CertParamDialog()
            if dialog.exec():
                name, organization, country, locality = dialog.get_parameters()
            return name, organization, country, locality
        except Exception as e:
            ExceptionHandler.unhandled_exception(e, "CertParameter_UI")


# Ask for info to generate a certificate
class CertParamDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Certificate Generation")
        self.setWindowIcon(QIcon(ICON_CERTIFICATE))
        # name = organization = country = locality = ''

        layout = QVBoxLayout()

        self.name_label = QLabel("Your Name:")
        self.name_input = QLineEdit(CERTIFICATE_NAME)
        self.name_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)

        self.organization_label = QLabel("Organization Name:")
        self.organization_input = QLineEdit()
        self.organization_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.organization_label)
        layout.addWidget(self.organization_input)

        self.country_label = QLabel("Country:")
        self.country_input = QLineEdit()
        self.country_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.country_label)
        layout.addWidget(self.country_input)

        self.locality_label = QLabel("Locality:")
        self.locality_input = QLineEdit()
        self.locality_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.locality_label)
        layout.addWidget(self.locality_input)

        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.ok_button.setEnabled(False)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)

        self.setWhatsThis(
            "This dialog allows you to input parameters for certificate generation."
        )

    def get_parameters(self):
        name = self.name_input.text()
        organization = self.organization_input.text()
        country = self.country_input.text()
        locality = self.locality_input.text()
        return name, organization, country, locality

    def save_toggle(self):
        if self.name_input.text():
            if self.country_input.text():
                if len(self.country_input.text()) == 2:
                    self.ok_button.setEnabled(True)
                else:
                    self.ok_button.setEnabled(False)
            else:
                self.ok_button.setEnabled(True)
        else:
            self.ok_button.setEnabled(False)