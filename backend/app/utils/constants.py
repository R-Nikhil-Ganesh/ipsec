"""
IPsec and IKE Protocol Constants, Registry Mappings, and Baseline Definitions
Based on RFC 7296 (IKEv2), RFC 2409 (IKEv1), RFC 4301 (IPsec Architecture), RFC 4303 (ESP)
"""

# IANA IKEv2 Transform Attribute Types (RFC 7296 Sec 3.3.2)
TRANSFORM_TYPE_ENCR = 1
TRANSFORM_TYPE_PRF = 2
TRANSFORM_TYPE_INTEG = 3
TRANSFORM_TYPE_DH = 4
TRANSFORM_TYPE_ESN = 5

# Encryption Transform IDs
ENCRYPTION_TRANSFORMS = {
    1: {"name": "DES-IV64", "rating": "CRITICAL", "desc": "Broken 56-bit DES with 64-bit IV"},
    2: {"name": "DES-CBC", "rating": "CRITICAL", "desc": "Broken 56-bit DES"},
    3: {"name": "3DES-CBC", "rating": "HIGH", "desc": "Legacy 64-bit block cipher vulnerable to Sweet32"},
    4: {"name": "RC5", "rating": "HIGH", "desc": "Deprecated cipher"},
    5: {"name": "IDEA", "rating": "HIGH", "desc": "Legacy cipher"},
    6: {"name": "CAST", "rating": "HIGH", "desc": "Legacy cipher"},
    7: {"name": "BLOWFISH", "rating": "HIGH", "desc": "Legacy 64-bit block cipher"},
    11: {"name": "NULL", "rating": "CRITICAL", "desc": "No encryption provided! Cleartext payload"},
    12: {"name": "AES-CBC", "rating": "MEDIUM", "desc": "Standard block cipher; vulnerable to padding oracles if integrity is absent"},
    13: {"name": "AES-CTR", "rating": "LOW", "desc": "Counter mode; requires explicit integrity verification"},
    18: {"name": "AES-GCM-8", "rating": "MEDIUM", "desc": "AES-GCM with short 64-bit ICV"},
    19: {"name": "AES-GCM-12", "rating": "LOW", "desc": "AES-GCM with 96-bit ICV"},
    20: {"name": "AES-GCM-16", "rating": "EXCELLENT", "desc": "Modern AEAD cipher with 128-bit ICV"},
    28: {"name": "CHACHA20-POLY1305", "rating": "EXCELLENT", "desc": "Modern AEAD stream cipher with high performance"}
}

# Integrity / Auth Transform IDs
INTEGRITY_TRANSFORMS = {
    0: {"name": "NONE", "rating": "CRITICAL", "desc": "No packet integrity protection"},
    1: {"name": "HMAC-MD5-96", "rating": "HIGH", "desc": "MD5 hash collisions; cryptographically broken"},
    2: {"name": "HMAC-SHA1-96", "rating": "HIGH", "desc": "SHA-1 collision attacks; deprecated by NIST"},
    3: {"name": "DES-MAC", "rating": "CRITICAL", "desc": "Broken MAC algorithm"},
    4: {"name": "KPDK-MD5", "rating": "CRITICAL", "desc": "Obsolete MAC algorithm"},
    5: {"name": "AES-XCBC-96", "rating": "MEDIUM", "desc": "Acceptable CBC-MAC variant for AES"},
    6: {"name": "HMAC-MD5-128", "rating": "HIGH", "desc": "MD5 hash family is broken"},
    7: {"name": "HMAC-SHA1-160", "rating": "HIGH", "desc": "SHA-1 is deprecated"},
    8: {"name": "AES-CMAC-96", "rating": "MEDIUM", "desc": "Acceptable CMAC"},
    9: {"name": "AES-128-GMAC", "rating": "EXCELLENT", "desc": "Galois MAC (AEAD)"},
    10: {"name": "AES-192-GMAC", "rating": "EXCELLENT", "desc": "Galois MAC (AEAD)"},
    11: {"name": "AES-256-GMAC", "rating": "EXCELLENT", "desc": "Galois MAC (AEAD)"},
    12: {"name": "HMAC-SHA2-256-128", "rating": "EXCELLENT", "desc": "Modern SHA-256 HMAC truncated to 128 bits"},
    13: {"name": "HMAC-SHA2-384-192", "rating": "EXCELLENT", "desc": "Modern SHA-384 HMAC truncated to 192 bits"},
    14: {"name": "HMAC-SHA2-512-256", "rating": "EXCELLENT", "desc": "Modern SHA-512 HMAC truncated to 256 bits"}
}

# Diffie-Hellman Transform IDs (RFC 7296 Sec 3.3.2)
DH_GROUPS = {
    1: {"name": "DH-Group-1 (MODP-768)", "bits": 768, "rating": "CRITICAL", "desc": "Easily factorable with modest compute; trivial break"},
    2: {"name": "DH-Group-2 (MODP-1024)", "bits": 1024, "rating": "HIGH", "desc": "Vulnerable to Logjam / precomputation attacks by nation-states"},
    5: {"name": "DH-Group-5 (MODP-1536)", "bits": 1536, "rating": "MEDIUM", "desc": "Insufficient security margin (< 128-bit symmetric equivalent)"},
    14: {"name": "DH-Group-14 (MODP-2048)", "bits": 2048, "rating": "ACCEPTABLE", "desc": "Standard minimum baseline (~112-bit symmetric equivalent)"},
    15: {"name": "DH-Group-15 (MODP-3072)", "bits": 3072, "rating": "STRONG", "desc": "Strong modular exponentiation group (~128-bit equivalent)"},
    16: {"name": "DH-Group-16 (MODP-4096)", "bits": 4096, "rating": "VERY_STRONG", "desc": "High security MODP group (~192-bit equivalent)"},
    19: {"name": "DH-Group-19 (ECP-256)", "bits": 256, "rating": "EXCELLENT", "desc": "NIST P-256 elliptic curve; fast and highly secure"},
    20: {"name": "DH-Group-20 (ECP-384)", "bits": 384, "rating": "EXCELLENT", "desc": "NIST P-384 elliptic curve; CNSA Suite B approved"},
    21: {"name": "DH-Group-21 (ECP-521)", "bits": 521, "rating": "EXCELLENT", "desc": "NIST P-521 elliptic curve; maximum commercial strength"},
    31: {"name": "DH-Group-31 (Curve25519)", "bits": 256, "rating": "EXCELLENT", "desc": "Modern Montgomery curve resistant to side channels"}
}

# IKE Exchange Types
IKE_EXCHANGE_TYPES = {
    1: "IKEv1 Identity Protection (Main Mode)",
    2: "IKEv1 Authentication Only",
    4: "IKEv1 Aggressive Mode",
    5: "IKEv1 Informational",
    34: "IKEv2 IKE_SA_INIT",
    35: "IKEv2 IKE_AUTH",
    36: "IKEv2 CREATE_CHILD_SA",
    37: "IKEv2 INFORMATIONAL"
}

# IPsec Ports and Protocols
PORT_ISAKMP = 500
PORT_NATT = 4500
IPPROTO_ESP = 50
IPPROTO_AH = 51

# Traffic Metadata Classification Labels
TRAFFIC_CLASSES = [
    "Web Browsing (HTTPS/HTTP)",
    "VoIP / Real-Time Audio",
    "Video Streaming",
    "Email (IMAP/SMTP)",
    "Encrypted Messaging",
    "ICMP / Network Diagnostic",
    "Bulk Transfer / Backup",
    "Interactive SSH / Remote Shell",
    "Unknown Encrypted Traffic"
]

# Risk Severities
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

# Observable State
STATE_OBSERVED = "OBSERVED"
STATE_INFERRED = "INFERRED"
STATE_UNKNOWN = "UNKNOWN"
