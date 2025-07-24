import os
import sys
import json
import requests
import tempfile
import subprocess
from datetime import datetime, timezone

#openssl shit
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response

issuerfromapple = "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer" # need this to check/compare
# DEVNULL -> no cmd output
# need openssl cmd line installed

# should work fine for macOS or Linux, not sure about windows

def RunOpensslExtract(P12Path, Password, CertPath, IssuerPath):
    try:
        subprocess.run(
            ["openssl", "pkcs12", "-in", P12Path, "-clcerts", "-nokeys", "-out", CertPath, "-passin", f"pass:{Password}"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["openssl", "pkcs12", "-in", P12Path, "-cacerts", "-nokeys", "-out", IssuerPath, "-passin", f"pass:{Password}"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        try:
            subprocess.run(
                ["openssl", "pkcs12", "-legacy", "-in", P12Path, "-clcerts", "-nokeys", "-out", CertPath, "-passin", f"pass:{Password}"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["openssl", "pkcs12", "-legacy", "-in", P12Path, "-cacerts", "-nokeys", "-out", IssuerPath, "-passin", f"pass:{Password}"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as E:
            Output = {"Status": "ERROR", "Reason": f"Openssl failed, is it installed?: {str(E)}"}
            print(json.dumps(Output))
            sys.exit(1)

# getting the .cer from apple to check, yes it downloads it each time.
def DownloadAppleIssuer(Destination):
    try:
        Response = requests.get(issuerfromapple, timeout=10)
        Response.raise_for_status()
        with open(Destination, "wb") as F:
            F.write(Response.content)
        PemPath = Destination.replace(".cer", ".pem")
        subprocess.run(["openssl", "x509", "-inform", "DER", "-in", Destination, "-out", PemPath], check=True)
        return PemPath
    except Exception as E:
        Output = {"Status": "ERROR", "Reason": f"Apple issuer didn't download, is it blocked or some shit?: {str(E)}"}
        print(json.dumps(Output))
        sys.exit(1)

# this is what that cryptography stuff was for
def GetOcspUrl(Cert):
    try:
        Aia = Cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for AccessDesc in Aia:
            if AccessDesc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return AccessDesc.access_location.value
    except Exception:
        return None

def LoadCert(Path):
    with open(Path, "rb") as F:
        return x509.load_pem_x509_certificate(F.read(), default_backend())

# better looking output
def FormatTimediff(Then):
    Now = datetime.now(timezone.utc)
    Delta = Then - Now
    Days = Delta.days
    Suffix = "ago" if Days < 0 else "from now"
    return f"{abs(Days)} days {Suffix}"

# extract oscp url -> check with issuer -> REVOKED or VALID
def CheckOcsp(CertPath, IssuerPath):
    Cert = LoadCert(CertPath)
    Issuer = LoadCert(IssuerPath)
    OcspUrl = GetOcspUrl(Cert)
    if not OcspUrl:
        Output = {"Status": "ERROR", "Reason": "Cert seems invalid, no oscp url in there?"}
        print(json.dumps(Output))
        return 2

    Builder = OCSPRequestBuilder().add_certificate(Cert, Issuer, hashes.SHA1())
    Request = Builder.build()
    Headers = {
        "Content-Type": "application/ocsp-request",
        "Accept": "application/ocsp-response"
    }

    try:
        Response = requests.post(
            OcspUrl,
            data=Request.public_bytes(encoding=serialization.Encoding.DER),
            headers=Headers,
            timeout=10
        )
        Response.raise_for_status()
        OcspResp = load_der_ocsp_response(Response.content)
        Status = OcspResp.certificate_status

        if Status == x509.ocsp.OCSPCertStatus.GOOD:
            Output = {"Status": "VALID"}
            if OcspResp.next_update:
                Output["ValidUntil"] = OcspResp.next_update.isoformat()
                Output["ValidFor"] = FormatTimediff(OcspResp.next_update)
        elif Status == x509.ocsp.OCSPCertStatus.REVOKED:
            RevokedAt = OcspResp.revocation_time_utc
            ProducedAt = OcspResp.produced_at_utc
            Output = {
                "Status": "REVOKED",
                "RevokedAt": RevokedAt.isoformat(),
                "ProducedAt": ProducedAt.isoformat(),
                "RevokedSince": FormatTimediff(RevokedAt)
            }
        else:
            Output = {"Status": "UNKNOWN"}

        print(json.dumps(Output, indent=2))
        return 0 if Output["Status"] == "VALID" else 1

    except Exception as E:
        Output = {"Status": "ERROR", "Reason": str(E)}
        print(json.dumps(Output))
        return 2

def Main(P12Path, Password):
    with tempfile.TemporaryDirectory() as TmpDir:
        CertPath = os.path.join(TmpDir, "Cert.pem") # directly getting the .p12 wasn't working so i had to extract .pem from it
        IssuerPath = os.path.join(TmpDir, "Issuer.pem") # same goes for the issuer
        RunOpensslExtract(P12Path, Password, CertPath, IssuerPath)
        if not os.path.exists(IssuerPath) or os.path.getsize(IssuerPath) == 0:
            IssuerCerPath = os.path.join(TmpDir, "AppleWWDRCAG3.cer")
            IssuerPath = DownloadAppleIssuer(IssuerCerPath)
        return CheckOcsp(CertPath, IssuerPath)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(json.dumps({"Status": "ERROR", "Reason": "use all args, like: python3 check.py cert.p12 password"}))
        sys.exit(1)
    sys.exit(Main(sys.argv[1], sys.argv[2]))
