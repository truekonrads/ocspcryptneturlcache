# Using CryptnetUrlCache to identify malware callbacks

## TL;DR

* CryptnetUrlCache is a directory which contains cached certificate validation data - OCSP and CRLs for WinInet and WinHTTP library calls (most Windows native programs do it)
* We can use the certificate serial number in OCSP requests and responses to retrieve the actual certificates from [Certificate Transparency](https://certificate.transparency.dev/howctworks/) log database such as [crt.sh](https://crt.sh). Subject Name and Subject Alternative Name will tell us what are the possible hostname values
* This is useful when you want to examine where programs may have connected to

## What is CryptnetUrlCache?
Windows operating systems since at least XP/2003 provide a cacheing facility in the [wininet](https://learn.microsoft.com/en-us/windows/win32/wininet/about-wininet) library/API. This API is used by vast majority of Windows native applications such as Internet Explorer but also RATs such as CobaltStrike to make calls to HTTP, HTTPS, FTP (and Gopher on XP/2003) protocols.

HTTPS connections as secured by SSL/TLS protocols make use of PKI certificates. These certificates need to be validated - this means not only checking if their cryptographic propreties are sound, but also validating if they have been revoked or not. Revocation data is placed on Certificate Revocation Lists (CRLs) and can also be retrieved online via Online Certificate Status Protocol ("OCSP"). One of the attributes in the OCSP requests is the serial number of the certificate. Serial numbers are meant to be unique per Certification Authority and is the primary way a specific certificate is references by the Certification Authority.

If we could get a serial number, we could find out what certificate was used. If we could find out what certificate was used, we could find out what may have been the hostname that malware was connecting to.

If executables were signed, there's a chance Windows went and validated the certficate validity and then code signing key may have been cached in there as well.

Windows caches these responses to speed up repeated connections in a directory called CryptnetUrlCache. This is a per "user-profile" directory and is in `%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache`. Services running as system will have their profile stores in `%windir%\System32\config\systemprofile`.

A [nice blogpost](https://u0041.co/blog/post/3) by [AbdulRhmanAlfaifi](https://github.com/AbdulRhmanAlfaifi) explores how to parse the CryptnetUrlCache. A corresponding tool in Python (CryptnetURLCacheParser)[https://github.com/AbdulRhmanAlfaifi/CryptnetURLCacheParser] is available as well. Example output is shown below:
```
PS C:\Users\admin> C:\Python312\python.exe C:\Users\admin\Documents\Code\CryptnetURLCacheParser\CryptnetUrlCacheParser.py
"LastDownloadTime","URL","FileSize","ETag","FullPath"
"2023-04-15T10:03:46.388216","1601-01-01T00:00:00.000004","http://x1.c.lencr.org/",717,"6439ef9c-2cd","C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Metadata\103621DE9CD5414CC2538780B4B75751"
"2024-03-05T06:43:35.646207","1601-01-01T00:00:00.000004","http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",1392,"","C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Metadata\1E2DBD58769A756A24A9D033F9B07F3D"
"2024-03-02T20:12:18.857327","1601-01-01T00:21:28.490192","http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQrHR6YzPN2BNbByL0VoiTIBBMAOAQUCrwIKReMpTlteg7OM8cus%2B37w3oCEAuJBTcSX0UQ1jcqECipKaU%3D",313,"","C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Metadata\50CD3D75D026C82E2E718570BD6F44D0_02835C6072261A584AE38D197B622594"
"2024-03-05T00:12:25.273681","1601-01-01T00:42:56.980381","http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab",4770,"746787a3f0d91:0","C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Metadata\57C8EDB95DF3F0AD4EE2DC2B8CFD4157"
"2024-02-29T07:14:31.982541","1601-01-01T00:21:28.490192","http://r3.o.lencr.org/MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D",503,"CF350E56F21904EFE154AE17208D067F985CADE1D6C6911F30BC810E45BFB980","C:\Users\admin\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\FA29C1BB6FD1E1E853C21E880ECD12C7"
...
```
As you can see, there's a mix of CRLs and OCSP requests.

## Converting serial number to hostname
The OCSP requests encode the requested information in the URL using the ASN.1 notation. Luckily the python `cryptography` library has a parser for this:


```python
from cryptography.x509 import ocsp
from urllib.parse import urlparse,unquote
import base64
from binascii import hexlify
url=r"http://r3.o.lencr.org/MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D"
path=unquote(urlparse(url).path.split('/')[-1])
data = base64.b64decode(path)
x=ocsp.load_der_ocsp_request(data)
print(f"Serial number: {hex(x.serial_number)[2:].upper()}")
print(f"Hash algorithm: {x.hash_algorithm.name}")
print(f"Issuer key hash: {hexlify(x.issuer_key_hash)}")
print(f"Issuer name hash: {hexlify(x.issuer_name_hash)}")
```

    Serial number: 349CAC261DE48DA54F81C5C20C750D356B0
    Hash algorithm: sha1
    Issuer key hash: b'142eb317b75856cbae500940e61faf9d8b14c2c6'
    Issuer name hash: b'48dac9a0fb2bd32d4ff0de68d2f567b735f9b3c4'
    

# Retrieving the certificate
We can now search for the certificate in the crt.sh database and display some properties about it. Not all certificates will be in the Certificate Transparency logs. Not all CAs participate and some certificates may be too old. For this other databases could be useful (VirusTotal, Censys, etc)


```python
import requests
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
def ask_crt_sh(sn:str)->list[x509.Certificate]:
    
    url=f"https://crt.sh/?serial={sn}&match=%3D&deduplicate=Y"
    list_of_certs=requests.get(url)
    bs=BeautifulSoup(list_of_certs.text)
    try:
        cert_rows=bs.findAll('table')[2].findAll('tr')[1:]
    except IndexError:
        return []
    certs=[]
    for tr in cert_rows:
        cert_id=tr.findAll('td')[0].text
        url=f"https://crt.sh/?d={cert_id}"
        # print(url)
        pem_data=requests.get(url).text.encode('utf8')
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        certs.append(cert)
    return certs
certs=ask_crt_sh("349CAC261DE48DA54F81C5C20C750D356B0")
certs
```




    [<Certificate(subject=<Name(CN=cache1-sgp1.steamcontent.com)>, ...)>,
     <Certificate(subject=<Name(CN=cache1-sgp1.steamcontent.com)>, ...)>]



You can see we have two certificates with same serial number. In this case it is becasue one of them is a (Pre-Certificate)[https://www.thesslstore.com/blog/ssl-precertificates/]. Pre-Certificates is a sort of a "bridge certificate" to enable Certificate Transparency to work. Either way, the subject names and subject alternative names will be the same.
 In theory we could also have two certificates with same serial number from different CAs but in practice this doesn't seem to happen. 

 Finally, we should just retrieve the names from certs:


```python
import cryptography
from cryptography.x509.oid import ExtensionOID
def get_names_from_cert(cert):
    # Assuming 'cert' is your loaded certificate
    try:
        # Get the SAN extension from the certificate
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = san_extension.value

        # Extract the SANs as strings
        san_list = []
        for name in san_names:
            if isinstance(name, cryptography.x509.DNSName):
                san_list.append(name.value)
            elif isinstance(name, cryptography.x509.IPAddress):
                san_list.append(str(name.value))
            # Include additional types as necessary, e.g., EmailAddress, URI, etc.

    except cryptography.x509.ExtensionNotFound:
        # Handle the case where the SAN extension is not present
        san_list = []
    subject=cert.subject.rfc4514_string()
    if subject.startswith("CN="):
        subject=subject[3:].split(",")[0]
    san_list.append(subject)
    return list(set(san_list))
for c in certs:
    print(get_names_from_cert(c))
```

    ['cache1-sgp1.steamcontent.com']
    ['cache1-sgp1.steamcontent.com']
    


```python
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
import subprocess
from urllib.parse import urlparse,unquote
from cryptography.x509.oid import ExtensionOID
import requests
from bs4 import BeautifulSoup
def get_serial_from_url(url):    
    path=unquote(urlparse(url).path.split('/')[-1])
    # print(path)
    data = base64.b64decode(path)
    x=ocsp.load_der_ocsp_request(data)
    return hex(x.serial_number)[2:].upper()

def get_names_from_cert(cert):
    # Assuming 'cert' is your loaded certificate
    try:
        # Get the SAN extension from the certificate
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = san_extension.value

        # Extract the SANs as strings
        san_list = []
        for name in san_names:
            if isinstance(name, cryptography.x509.DNSName):
                san_list.append(name.value)
            elif isinstance(name, cryptography.x509.IPAddress):
                san_list.append(str(name.value))
            # Include additional types as necessary, e.g., EmailAddress, URI, etc.

    except cryptography.x509.ExtensionNotFound:
        # Handle the case where the SAN extension is not present
        san_list = []
    subject=cert.subject.rfc4514_string()
    if subject.startswith("CN="):
        subject=subject[3:].split(",")[0]
    san_list.append(subject)
    return list(set(san_list))
    
def ask_crt_sh(sn:str)->list[x509.Certificate]:
    url=f"https://crt.sh/?serial={sn}&match=%3D&deduplicate=Y"
    list_of_certs=requests.get(url)
    bs=BeautifulSoup(list_of_certs.text)
    try:
        cert_rows=bs.findAll('table')[2].findAll('tr')[1:]
    except IndexError:
        return []
    certs=[]
    for tr in cert_rows:
        cert_id=tr.findAll('td')[0].text
        url=f"https://crt.sh/?d={cert_id}"
        # print(url)
        pem_data=requests.get(url).text.encode('utf8')
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        certs.append(cert)
    return certs
```

For quick and dirty dbeugging, we can ask certutil to dump a list of cached urls on our local system


```python
out=subprocess.run('certutil -urlcache',shell=True,universal_newlines=True,capture_output=True)
urls=[x for x in out.stdout.split("\n\n") if "/MF" in x and x.startswith('http')]
# Just first 10
for u in urls[:10]:
    sn=get_serial_from_url(u)
    certs=ask_crt_sh(sn)
    subjectnames=[]
    for c in certs:
        subjectnames.extend(get_names_from_cert(c))
    print(set(subjectnames))
```

    {'Sectigo RSA Code Signing CA'}
    {'cache6-sgp1.steamcontent.com'}
    {'Sectigo Public Code Signing CA R36'}
    {'GTS Root R1'}
    {'client-update.akamai.steamstatic.com', 'client-update.steamstatic.com'}
    {'cache10-sgp1.steamcontent.com'}
    {'1password.com', 'www.1password.com'}
    set()
    set()
    {'store.steampowered.com', 'login.steampowered.com', 'partner.steampowered.com', 'underlords.com', 'partner.steamgames.com', 'support.steampowered.com', 'help.steampowered.com', 'steamcommunity.com', 'www.valvesoftware.com', 'api.steampowered.com'}
    


```python

```
