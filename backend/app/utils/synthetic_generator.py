"""
Synthetic PCAP Generator for Controlled Laboratory Datasets
Generates real, valid binary PCAPs using Scapy with accurate IKEv1/IKEv2 headers,
transforms, ESP flows, and anomaly patterns.
Conforms to RFC 7296, RFC 2409, and RFC 4303.
"""
import os
import struct
import time
import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import ESP
from scapy.layers.isakmp import ISAKMP

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data", "sample_pcaps")


def ensure_dirs():
    os.makedirs(SAMPLE_DIR, exist_ok=True)


def build_ikev2_sa_payload(encr_id=20, integ_id=12, dh_id=19, key_len=256):
    """
    Builds an IKEv2 Security Association payload containing Proposals and Transforms.
    """
    # Transform ENCR
    t_encr = struct.pack("!BBHBBH", 3, 0, 12, 1, 0, encr_id)  # Type 1 = ENCR
    t_encr += struct.pack("!HH", 0x8000 | 14, key_len)  # Key length attribute

    # Transform PRF
    t_prf = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 2)  # Type 2 = PRF (PRF_HMAC_SHA2_256)

    # Transform INTEG (if not AEAD)
    t_integ = b""
    if encr_id not in (20, 28):  # Not GCM or Poly1305
        t_integ = struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integ_id)

    # Transform DH
    t_dh = struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_id)  # Type 4 = DH

    transforms = t_encr + t_prf + t_integ + t_dh
    num_transforms = 3 if encr_id in (20, 28) else 4

    prop_len = 8 + len(transforms)
    # Proposal: Last (0), Res (0), Length (2B), Prop #1, Proto 1 (IKE), SPI Size 0, Num Transforms
    prop = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, num_transforms) + transforms

    sa_len = 4 + len(prop)
    # SA Payload Header: Next (34 for KE), Res (0), Length (2B)
    sa_payload = struct.pack("!BBH", 34, 0, sa_len) + prop
    return sa_payload


def build_ikev2_ke_payload(dh_id=19, next_payload=40):
    """Builds an IKEv2 Key Exchange (KE) payload."""
    # Key length: 64 bytes for Group 19 (32 bytes X, 32 bytes Y), 128 bytes for Group 2
    ke_data_len = 64 if dh_id == 19 else (128 if dh_id == 2 else 256)
    ke_data = os.urandom(ke_data_len)
    payload_len = 4 + 4 + len(ke_data)
    ke_head = struct.pack("!BBHHH", next_payload, 0, payload_len, dh_id, 0)
    return ke_head + ke_data


def build_ikev2_nonce_payload(next_payload=0):
    """Builds an IKEv2 Nonce (Ni/Nr) payload."""
    nonce = os.urandom(32)
    payload_len = 4 + len(nonce)
    return struct.pack("!BBH", next_payload, 0, payload_len) + nonce


def build_ikev2_header(init_spi, resp_spi, next_payload, exch_type, flags, msg_id, payload_body):
    """Constructs the standard 28-byte IKEv2 header."""
    total_len = 28 + len(payload_body)
    ver = 0x20  # IKEv2
    hdr = struct.pack("!8s8sBBBBII", init_spi, resp_spi, next_payload, ver, exch_type, flags, msg_id, total_len)
    return hdr + payload_body


def build_ikev1_sa_payload(encr_val=5, hash_val=1, dh_val=2, life_sec=3600):
    """Builds an IKEv1 SA payload with Transforms (3DES, MD5, DH2)."""
    # Attribute 1: Encr, 2: Hash, 3: Auth (1=PSK), 4: Group, 11: LifeType (1=sec), 12: LifeVal
    attrs = struct.pack("!HHHH", 0x8001, encr_val, 0x8002, hash_val)
    attrs += struct.pack("!HHHH", 0x8003, 1, 0x8004, dh_val)
    attrs += struct.pack("!HHHH", 0x800B, 1, 0x800C, life_sec)

    t_len = 8 + len(attrs)
    # Transform: Next 0, Res 0, Len, Trans #1, Trans ID 1, Res 0
    transform = struct.pack("!BBHBBH", 0, 0, t_len, 1, 1, 0) + attrs

    p_len = 8 + len(transform)
    # Proposal: Next 0, Res 0, Len, Prop #1, Proto 1 (ISAKMP), SPI Sz 0, 1 transform
    proposal = struct.pack("!BBHBBBB", 0, 0, p_len, 1, 1, 0, 1) + transform

    # DOI 1 (IPSEC), Situation 1 (IDENTITY)
    sa_body = struct.pack("!II", 1, 1) + proposal
    sa_len = 4 + len(sa_body)
    return struct.pack("!BBH", 0, 0, sa_len) + sa_body


def generate_all_pcaps():
    ensure_dirs()
    print("Generating controlled laboratory PCAPs...")

    # ==========================================
    # 1. Strong VPN (IKEv2, AES-256-GCM, DH-19, PFS ON, Replay ON)
    # ==========================================
    pkts = []
    base_time = time.time() - 300
    init_spi = os.urandom(8)
    resp_spi = os.urandom(8)

    # Packet 1: IKE_SA_INIT Request
    sa_p = build_ikev2_sa_payload(encr_id=20, integ_id=0, dh_id=19, key_len=256)
    ke_p = build_ikev2_ke_payload(dh_id=19, next_payload=40)
    nonce_p = build_ikev2_nonce_payload(next_payload=0)
    body1 = sa_p + ke_p + nonce_p
    ike1 = build_ikev2_header(init_spi, b'\x00'*8, 33, 34, 0x08, 0, body1)
    p1 = IP(src="192.168.1.100", dst="203.0.113.1")/UDP(sport=500, dport=500)/ike1
    p1.time = base_time
    pkts.append(p1)

    # Packet 2: IKE_SA_INIT Response
    body2 = sa_p + ke_p + nonce_p
    ike2 = build_ikev2_header(init_spi, resp_spi, 33, 34, 0x20, 0, body2)
    p2 = IP(src="203.0.113.1", dst="192.168.1.100")/UDP(sport=500, dport=500)/ike2
    p2.time = base_time + 0.02
    pkts.append(p2)

    # Packet 3 & 4: CREATE_CHILD_SA (PFS Key Exchange active)
    body3 = build_ikev2_ke_payload(dh_id=19, next_payload=0)
    ike3 = build_ikev2_header(init_spi, resp_spi, 34, 36, 0x08, 1, body3)
    p3 = IP(src="192.168.1.100", dst="203.0.113.1")/UDP(sport=4500, dport=4500)/(b'\x00\x00\x00\x00' + ike3)
    p3.time = base_time + 0.10
    pkts.append(p3)

    # ESP Packets (Traffic inside Tunnel, Web / Video mix, monotonically increasing seq numbers)
    esp_spi = 0x1a2b3c4d
    t_curr = base_time + 0.20
    for seq in range(1, 35):
        # High MTU packets ~1200-1420 bytes
        sz = 1420 if seq % 3 != 0 else 740
        esp_payload = struct.pack("!II", esp_spi, seq) + os.urandom(sz - 8)
        # UDP 4500 NAT-T encapsulation
        p_esp = IP(src="192.168.1.100", dst="203.0.113.1")/UDP(sport=4500, dport=4500)/esp_payload
        p_esp.time = t_curr
        pkts.append(p_esp)
        t_curr += 0.015

    scapy.wrpcap(os.path.join(SAMPLE_DIR, "strong_vpn.pcap"), pkts)
    print("  -> Generated strong_vpn.pcap")

    # ==========================================
    # 2. Weak Crypto VPN (IKEv1, 3DES, HMAC-MD5, DH-2, PFS OFF, Replay ON)
    # ==========================================
    pkts = []
    base_time = time.time() - 300
    init_cookie = os.urandom(8)
    resp_cookie = os.urandom(8)

    # IKEv1 Main Mode Exchange
    sa_v1 = build_ikev1_sa_payload(encr_val=5, hash_val=1, dh_val=2, life_sec=36000)
    hdr_v1 = struct.pack("!8s8sBBBBII", init_cookie, b'\x00'*8, 1, 0x10, 2, 0, 0, 28 + len(sa_v1)) + sa_v1
    p1 = IP(src="10.0.0.15", dst="198.51.100.50")/UDP(sport=500, dport=500)/hdr_v1
    p1.time = base_time
    pkts.append(p1)

    # Response
    hdr_v1_resp = struct.pack("!8s8sBBBBII", init_cookie, resp_cookie, 1, 0x10, 2, 0, 0, 28 + len(sa_v1)) + sa_v1
    p2 = IP(src="198.51.100.50", dst="10.0.0.15")/UDP(sport=500, dport=500)/hdr_v1_resp
    p2.time = base_time + 0.03
    pkts.append(p2)

    # ESP Packets with 3DES 8-byte block characteristic
    esp_spi = 0x55aa66bb
    t_curr = base_time + 0.15
    for seq in range(1, 30):
        sz = 800
        esp_raw = struct.pack("!II", esp_spi, seq) + os.urandom(sz - 8)
        p_esp = IP(src="10.0.0.15", dst="198.51.100.50", proto=50)/esp_raw
        p_esp.time = t_curr
        pkts.append(p_esp)
        t_curr += 0.02

    scapy.wrpcap(os.path.join(SAMPLE_DIR, "weak_crypto_vpn.pcap"), pkts)
    print("  -> Generated weak_crypto_vpn.pcap")

    # ==========================================
    # 3. Configuration Drift Demo PCAP (Current degraded tunnel)
    # Downgraded: AES-128-CBC, DH Group 14, PFS disabled!
    # ==========================================
    pkts = []
    base_time = time.time() - 300
    init_spi = os.urandom(8)
    resp_spi = os.urandom(8)

    # IKEv2 with AES-128-CBC, HMAC-SHA1, DH Group 14
    sa_drift = build_ikev2_sa_payload(encr_id=12, integ_id=2, dh_id=14, key_len=128)
    ke_drift = build_ikev2_ke_payload(dh_id=14, next_payload=40)
    nonce_drift = build_ikev2_nonce_payload(next_payload=0)
    body_drift = sa_drift + ke_drift + nonce_drift
    ike_d1 = build_ikev2_header(init_spi, b'\x00'*8, 33, 34, 0x08, 0, body_drift)
    p_d1 = IP(src="192.168.10.5", dst="198.51.100.20")/UDP(sport=500, dport=500)/ike_d1
    p_d1.time = base_time
    pkts.append(p_d1)

    ike_d2 = build_ikev2_header(init_spi, resp_spi, 33, 34, 0x20, 0, body_drift)
    p_d2 = IP(src="198.51.100.20", dst="192.168.10.5")/UDP(sport=500, dport=500)/ike_d2
    p_d2.time = base_time + 0.02
    pkts.append(p_d2)

    # ESP Packets
    esp_spi = 0x88776655
    t_curr = base_time + 0.10
    for seq in range(1, 30):
        esp_raw = struct.pack("!II", esp_spi, seq) + os.urandom(600)
        p_esp = IP(src="192.168.10.5", dst="198.51.100.20")/UDP(sport=4500, dport=4500)/esp_raw
        p_esp.time = t_curr
        pkts.append(p_esp)
        t_curr += 0.02

    scapy.wrpcap(os.path.join(SAMPLE_DIR, "config_drift_vpn.pcap"), pkts)
    print("  -> Generated config_drift_vpn.pcap")

    # ==========================================
    # 4. Anomalous VPN (Handshake flood, duplicate sequence numbers / replay violation)
    # ==========================================
    pkts = []
    base_time = time.time() - 300
    # Rapid burst of 20 IKE_SA_INIT requests
    for i in range(22):
        fake_spi = os.urandom(8)
        body_anom = build_ikev2_sa_payload(encr_id=20, dh_id=19) + build_ikev2_nonce_payload(0)
        ike_anom = build_ikev2_header(fake_spi, b'\x00'*8, 33, 34, 0x08, 0, body_anom)
        p = IP(src=f"10.0.4.{i % 4 + 1}", dst="198.51.100.1")/UDP(sport=500 + i, dport=500)/ike_anom
        p.time = base_time + i * 0.005
        pkts.append(p)

    # ESP packets with deliberate DUPLICATE sequence numbers (Replay attack simulation)
    esp_spi = 0xdeadbeef
    t_curr = base_time + 0.20
    for seq in [1, 2, 3, 4, 3, 4, 5, 6, 5, 7, 8, 9, 8]:
        esp_raw = struct.pack("!II", esp_spi, seq) + os.urandom(500)
        p_esp = IP(src="10.0.4.1", dst="198.51.100.1", proto=50)/esp_raw
        p_esp.time = t_curr
        pkts.append(p_esp)
        t_curr += 0.01

    scapy.wrpcap(os.path.join(SAMPLE_DIR, "anomalous_vpn.pcap"), pkts)
    print("  -> Generated anomalous_vpn.pcap")

    # ==========================================
    # 5. Legacy VPN (IKEv1 with Single DES)
    # ==========================================
    pkts = []
    base_time = time.time() - 300
    init_cookie = os.urandom(8)
    # DES-CBC (val 1), MD5 (val 1), DH Group 1 (val 1)
    sa_legacy = build_ikev1_sa_payload(encr_val=1, hash_val=1, dh_val=1, life_sec=7200)
    hdr_legacy = struct.pack("!8s8sBBBBII", init_cookie, b'\x00'*8, 1, 0x10, 2, 0, 0, 28 + len(sa_legacy)) + sa_legacy
    p_leg = IP(src="172.16.1.1", dst="172.16.2.1")/UDP(sport=500, dport=500)/hdr_legacy
    p_leg.time = base_time
    pkts.append(p_leg)

    esp_spi = 0x00112233
    t_curr = base_time + 0.1
    for seq in range(1, 20):
        esp_raw = struct.pack("!II", esp_spi, seq) + os.urandom(300)
        p_esp = IP(src="172.16.1.1", dst="172.16.2.1", proto=50)/esp_raw
        p_esp.time = t_curr
        pkts.append(p_esp)
        t_curr += 0.03

    scapy.wrpcap(os.path.join(SAMPLE_DIR, "legacy_vpn.pcap"), pkts)
    print("  -> Generated legacy_vpn.pcap")
    print("All sample PCAPs successfully generated.")


if __name__ == "__main__":
    generate_all_pcaps()
