// --------------------------------------------------------------------------------------------
//
// This is a POC providing the absolutely necessary functionality to work with the crypt32.dll
// provided by Microsoft Windows. It was never intended to be used in production, ever.
// Please write modular OO or functional code. Thank you.
//
// --------------------------------------------------------------------------------------------

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const wchar_t = require('ref-wchar-napi');
const StructType = require('ref-struct-di')(ref);
const fs = require('fs');

const wchar_string = wchar_t.string;

// definitions and constants are from the following header file
//
// https://github.com/wine-mirror/wine/blob/master/include/wincrypt.h

// define constants 

const X509_ASN_ENCODING = 0x00000001;
const PKCS_7_ASN_ENCODING = 0x00010000;
const PROV_RSA_FULL = 1;
const AT_KEYEXCHANGE = 1;
const CERT_KEY_PROV_INFO_PROP_ID = 2;
const CERT_STORE_ADD_REPLACE_EXISTING = 3;

const HCERTSTORE = 'void *';
const DWORD = ref.types.ulong;
const BYTE_PTR = ref.refType(ref.types.uint8);
const LPWSTR = wchar_string;

const _CRYPTOAPI_BLOB = StructType({
    cbData: DWORD,
    pbData: BYTE_PTR
});

const CRYPT_INTEGER_BLOB = _CRYPTOAPI_BLOB;
const CRYPT_OBJID_BLOB = _CRYPTOAPI_BLOB;
const CERT_NAME_BLOB = _CRYPTOAPI_BLOB;

const CRYPT_BIT_BLOB = StructType({
    cbData: DWORD,
    pbData: BYTE_PTR,
    cUnusedBits: DWORD
});

const CRYPT_ALGORITHM_IDENTIFIER = StructType({
    pszObjId: 'string',
    Parameters: CRYPT_OBJID_BLOB
});

const FILETIME = StructType({
    dwLowDateTime: DWORD,
    dwHighDateTime: DWORD
});

const CERT_PUBLIC_KEY_INFO = StructType({
    Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    PublicKey: CRYPT_BIT_BLOB
});

const CERT_EXTENSION = StructType({
    pszObjId: 'string',
    fCritical: 'bool',
    Value: CRYPT_OBJID_BLOB
});

const PCERT_EXTENSION = ref.refType(CERT_EXTENSION);

const _CERT_INFO = StructType({
    dwVersion: DWORD,
    SerialNumber: CRYPT_INTEGER_BLOB,
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    Issuer: CERT_NAME_BLOB,
    NotBefore: FILETIME,
    NotAfter: FILETIME,
    Subject: CERT_NAME_BLOB,
    SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    IssuerUniqueId: CRYPT_BIT_BLOB,
    SubjectUniqueId: CRYPT_BIT_BLOB,
    cExtension: DWORD,
    rgExtension: PCERT_EXTENSION
});

const PCERT_INFO = ref.refType(_CERT_INFO);

const _CERT_CONTEXT = StructType({
    dwCertEncodingType: DWORD,
    pbCertEncoded: BYTE_PTR,
    cbCertEncoded: DWORD,
    pCertInfo: PCERT_INFO,
    hCertStore: HCERTSTORE
});

const PCCERT_CONTEXT = ref.refType(_CERT_CONTEXT);
const PPCCERT_CONTEXT = ref.refType(PCCERT_CONTEXT);

const _CRYPT_KEY_PROV_PARAM = StructType({
    dwParam: DWORD,
    pbData: BYTE_PTR,
    cbData: DWORD,
    dwFlags: DWORD
});

const PCRYPT_KEY_PROV_PARAM = ref.refType(_CRYPT_KEY_PROV_PARAM);

const _CRYPT_KEY_PROV_INFO = StructType({
    pwszContainerName: LPWSTR,        // LPWSTR
    pwszProvName: LPWSTR,             // LPWSTR
    dwProvType: DWORD,
    dwFlags: DWORD,
    cProvParam: DWORD,
    rgProvParam: PCRYPT_KEY_PROV_PARAM,
    dwKeySpec: DWORD
});

// -------------------------------------------------------------------------------------

// define functions
//
// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt
//
// HINT: The prefix 'p' indicates a pointer to a structure

const libcrypto = ffi.Library('C:/windows/system32/crypt32.dll', {
    'CertOpenSystemStoreA': [HCERTSTORE, ['int', 'string']],
    'CertCloseStore': ['bool', [HCERTSTORE, 'int']],
    'CertCreateCertificateContext': [PCCERT_CONTEXT, [DWORD, BYTE_PTR, DWORD]],
    'CertSetCertificateContextProperty': ['bool', [PCCERT_CONTEXT, DWORD, DWORD, 'void*']],
    'CertAddCertificateContextToStore': ['bool', [HCERTSTORE, PCCERT_CONTEXT, DWORD, PPCCERT_CONTEXT]]
});

const knl32 = ffi.Library('kernel32.dll', {
    GetLastError: ['uint32', []],
    FormatMessageW: [
        'uint',
        ['uint', 'pointer', 'uint', 'uint', 'pointer', 'uint', 'pointer'],
    ],
})

function get_last_err_msg() {
    const errcode = knl32.GetLastError()
    let errMsg = ''

    /* istanbul ignore if  */
    if (errcode) {
        const len = 255
        const buf = Buffer.alloc(len)
        // tslint:disable-next-line:no-bitwise
        const p = 0x00001000 | 0x00000200  // FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
        const langid = 0x0409              // 0x0409: US, 0x0000: Neutral locale language
        const msglen = knl32.FormatMessageW(p, null, errcode, langid, buf, len, null)

        errMsg = msglen
            ? errcode + ': ' + ref.reinterpretUntilZeros(buf, 2).toString('ucs2')
            : `${errcode}: unknown error message`
    }

    return errMsg
}


// ------------------------------------------------------------------------

console.log('Trying to open certificate store');

const hSystemStore = libcrypto.CertOpenSystemStoreA(ref.NULL, 'MY')

if (ref.isNull(hSystemStore)) {
    console.error('Cannot open store');
}

console.info(hSystemStore);

// ------------------------------------------------------------------------

// FIXME
//
// current the certificate file in .cer (base64 encoded) was converted to .der (binary encoded)
// via a web application. This shall be automatized using a node.js library.
// load cer file (which is base64 encoded) and covert to binary DER format
// const pbCertEncoded = fs.readFileSynch('test.cer');

// pbCertEncoded represents a certificate in X.509/DER encoding!
const pbCertEncoded = fs.readFileSync('test.der');

const pCertContext = libcrypto.CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbCertEncoded, pbCertEncoded.length);

if (ref.isNull(pCertContext)) {
    console.error('Cannot create cert context, reason = ' + get_last_err_msg());
}

// ------------------------------------------------------------------------

const keyinfo = new _CRYPT_KEY_PROV_INFO();

// FIXME the following two strings shall be using 16 bit unicode characters instead of utf8 or whatever
keyinfo.pwszProvName = 'MY Key Storage Provider';
keyinfo.pwszContainerName = 'my_id my_api_key';       // here comes the id and the api_key
keyinfo.dwProvType = PROV_RSA_FULL;
keyinfo.dwKeySpec = AT_KEYEXCHANGE;

const keyinfoBuffer = keyinfo.ref();

if (!libcrypto.CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, keyinfoBuffer)) {
    console.error('Cannot set cert context property, reason = ' + get_last_err_msg());
}

if (!libcrypto.CertAddCertificateContextToStore(hSystemStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, ref.NULL)) {
    console.error('Cannot add certificate to store, reason = ' + get_last_err_msg());
}

if (!libcrypto.CertCloseStore(hSystemStore, ref.NULL)) {
    console.log("Unable to close the  system store.\n");
} else {
    console.log('Certificate store successfully closed');
}