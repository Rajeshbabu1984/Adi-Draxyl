"""
Generate self-signed SSL certificate for HTTPS
For production, use proper certificates from Let's Encrypt or a CA
"""
from OpenSSL import crypto
import os

def generate_self_signed_cert():
    # Create key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create certificate
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Draxyl"
    cert.get_subject().OU = "Security"
    cert.get_subject().CN = "localhost"
    
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    # Write certificate
    with open("cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Write private key
    with open("key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    print("✅ SSL certificate generated successfully!")
    print("📄 cert.pem - Certificate file")
    print("🔑 key.pem - Private key file")
    print("")
    print("⚠️  NOTE: This is a self-signed certificate for development.")
    print("⚠️  For production, use Let's Encrypt or a trusted CA.")

if __name__ == "__main__":
    generate_self_signed_cert()
