"""
IKE / ISAKMP Protocol Analyzer (IKEv1 and IKEv2)
Extracts cryptographic transforms, key exchange groups, exchange modes, and authentication indicators.
"""
from typing import Dict, Any, List, Optional, Tuple
import struct
from scapy.layers.isakmp import ISAKMP
from app.utils.constants import (
    ENCRYPTION_TRANSFORMS,
    INTEGRITY_TRANSFORMS,
    DH_GROUPS,
    IKE_EXCHANGE_TYPES,
    TRANSFORM_TYPE_ENCR,
    TRANSFORM_TYPE_INTEG,
    TRANSFORM_TYPE_DH,
    STATE_OBSERVED,
    STATE_INFERRED,
    STATE_UNKNOWN,
)


class IKEParser:
    def __init__(self):
        self.observed_ike_version: Optional[str] = None
        self.observed_exchanges: List[str] = []
        self.transforms_encr: List[Dict[str, Any]] = []
        self.transforms_integ: List[Dict[str, Any]] = []
        self.transforms_dh: List[Dict[str, Any]] = []
        self.pfs_observed: Optional[bool] = None
        self.nat_traversal_observed: bool = False
        self.evidence_log: List[Dict[str, Any]] = []
        self.ike_packet_count: int = 0
        self.initiator_spi: Optional[str] = None
        self.responder_spi: Optional[str] = None
        self.observed_lifetimes: List[int] = []

    def parse_packet(self, packet_idx: int, raw_bytes: bytes, ip_src: str, ip_dst: str, port_src: int, port_dst: int) -> Dict[str, Any]:
        """
        Parses an IKE/ISAKMP UDP packet directly from raw bytes and/or Scapy layer.
        Handles UDP 500 and UDP 4500 (with or without Non-ESP Marker).
        """
        data = raw_bytes
        # In NAT-T (UDP 4500), IKE packets are prepended with a 4-byte Non-ESP Marker (all zeros 0x00000000)
        if port_src == 4500 or port_dst == 4500:
            self.nat_traversal_observed = True
            if len(data) >= 4 and data[:4] == b'\x00\x00\x00\x00':
                data = data[4:]  # Strip non-ESP marker

        if len(data) < 28:
            return {"parsed": False, "reason": "Payload too short for ISAKMP header (<28 bytes)"}

        self.ike_packet_count += 1

        # ISAKMP Header:
        # Initiator SPI (8B), Responder SPI (8B), Next Payload (1B), Version (1B),
        # Exchange Type (1B), Flags (1B), Message ID (4B), Length (4B)
        init_spi, resp_spi, next_payload, ver_byte, exch_type, flags, msg_id, length = struct.unpack("!8s8sBBBBII", data[:28])
        init_spi_hex = init_spi.hex()
        resp_spi_hex = resp_spi.hex()

        if not self.initiator_spi:
            self.initiator_spi = init_spi_hex
        if not self.responder_spi and resp_spi_hex != "0000000000000000":
            self.responder_spi = resp_spi_hex

        major_ver = (ver_byte >> 4) & 0x0F
        minor_ver = ver_byte & 0x0F
        ike_ver_str = f"IKEv{major_ver}"
        if not self.observed_ike_version:
            self.observed_ike_version = ike_ver_str

        exch_name = IKE_EXCHANGE_TYPES.get(exch_type, f"Exchange-{exch_type}")
        if exch_name not in self.observed_exchanges:
            self.observed_exchanges.append(exch_name)

        packet_evidence = {
            "packet_index": packet_idx,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "ports": f"{port_src}->{port_dst}",
            "ike_version": ike_ver_str,
            "exchange_type": exch_name,
            "flags": flags,
            "message_id": msg_id,
            "initiator_spi": init_spi_hex,
            "responder_spi": resp_spi_hex,
            "payloads_found": []
        }

        # Parse payloads iteratively
        curr_offset = 28
        curr_payload_type = next_payload
        payload_limit = min(len(data), length)

        while curr_offset + 4 <= payload_limit and curr_payload_type != 0:
            if curr_offset + 4 > len(data):
                break
            p_next, p_res, p_len = struct.unpack("!BBH", data[curr_offset:curr_offset + 4])
            if p_len < 4 or curr_offset + p_len > len(data):
                break

            payload_body = data[curr_offset + 4: curr_offset + p_len]
            packet_evidence["payloads_found"].append(curr_payload_type)

            if major_ver == 2:
                self._parse_ikev2_payload(packet_idx, curr_payload_type, payload_body, packet_evidence)
            else:
                self._parse_ikev1_payload(packet_idx, curr_payload_type, payload_body, packet_evidence)

            curr_offset += p_len
            curr_payload_type = p_next

        self.evidence_log.append(packet_evidence)
        return packet_evidence

    def _parse_ikev2_payload(self, packet_idx: int, p_type: int, body: bytes, evidence: Dict[str, Any]):
        """
        Parses IKEv2 Payloads (RFC 7296):
        p_type 33: Security Association (SA)
        p_type 34: Key Exchange (KE)
        p_type 40: Nonce (Ni/Nr)
        p_type 41: Notify (N)
        p_type 43: Vendor ID (V)
        p_type 44: Traffic Selector Initiator (TSi)
        p_type 45: Traffic Selector Responder (TSr)
        p_type 46: Encrypted and Authenticated (SK)
        """
        if p_type == 33:  # SA Payload
            # Contains Proposals
            self._parse_ikev2_sa_proposals(packet_idx, body, evidence)
        elif p_type == 34:  # Key Exchange (KE)
            if len(body) >= 4:
                dh_group, reserved = struct.unpack("!HH", body[:4])
                dh_info = DH_GROUPS.get(dh_group, {"name": f"DH-Group-{dh_group}", "bits": 0, "rating": "UNKNOWN"})
                transform_entry = {
                    "packet": packet_idx,
                    "dh_group": str(dh_group),
                    "name": dh_info["name"],
                    "rating": dh_info.get("rating", "UNKNOWN"),
                    "key_exchange_len": len(body) - 4
                }
                if not any(d["dh_group"] == str(dh_group) for d in self.transforms_dh):
                    self.transforms_dh.append(transform_entry)
                evidence["observed_dh_ke"] = transform_entry

        elif p_type == 41:  # Notify Payload
            if len(body) >= 4:
                protocol_id, spi_size, notify_msg_type = struct.unpack("!BBH", body[:4])
                # Check for NAT detection notify types (16388 NAT_DETECTION_SOURCE_IP, 16389 NAT_DETECTION_DESTINATION_IP)
                if notify_msg_type in (16388, 16389, 16393):
                    self.nat_traversal_observed = True
                    evidence["nat_detection_notify"] = notify_msg_type

    def _parse_ikev2_sa_proposals(self, packet_idx: int, body: bytes, evidence: Dict[str, Any]):
        """
        Walks Proposals and Transforms in IKEv2 SA payload.
        Proposal: Last/More (1B), Res (1B), Prop Length (2B), Prop # (1B), Protocol ID (1B), SPI Size (1B), # Transforms (1B)
        """
        offset = 0
        while offset + 8 <= len(body):
            p_last, _, p_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack("!BBHBBBB", body[offset:offset + 8])
            if p_len < 8 or offset + p_len > len(body):
                break

            prop_data = body[offset + 8 + spi_sz: offset + p_len]
            t_offset = 0

            for _ in range(num_transforms):
                if t_offset + 8 > len(prop_data):
                    break
                t_last, _, t_len, t_type, _, t_id = struct.unpack("!BBHBBH", prop_data[t_offset:t_offset + 8])
                if t_len < 8:
                    break

                # Extract transform attributes (like key length)
                attr_offset = 8
                key_len = None
                while attr_offset + 4 <= t_len and t_offset + attr_offset + 4 <= len(prop_data):
                    attr_type, attr_val = struct.unpack("!HH", prop_data[t_offset + attr_offset: t_offset + attr_offset + 4])
                    # If highest bit of attr_type is 1 (0x8000), basic attribute (value is in attr_val)
                    if attr_type & 0x8000:
                        type_code = attr_type & 0x7FFF
                        if type_code == 14:  # Key Length in bits
                            key_len = attr_val
                    attr_offset += 4

                if t_type == TRANSFORM_TYPE_ENCR:
                    encr_info = ENCRYPTION_TRANSFORMS.get(t_id, {"name": f"ENCR_{t_id}", "rating": "UNKNOWN"})
                    name = encr_info["name"]
                    if key_len:
                        name = f"{name}-{key_len}"
                    self.transforms_encr.append({
                        "packet": packet_idx,
                        "id": t_id,
                        "name": name,
                        "key_len": key_len,
                        "rating": encr_info.get("rating", "UNKNOWN")
                    })
                elif t_type == TRANSFORM_TYPE_INTEG:
                    integ_info = INTEGRITY_TRANSFORMS.get(t_id, {"name": f"AUTH_{t_id}", "rating": "UNKNOWN"})
                    self.transforms_integ.append({
                        "packet": packet_idx,
                        "id": t_id,
                        "name": integ_info["name"],
                        "rating": integ_info.get("rating", "UNKNOWN")
                    })
                elif t_type == TRANSFORM_TYPE_DH:
                    dh_info = DH_GROUPS.get(t_id, {"name": f"DH-Group-{t_id}", "bits": 0, "rating": "UNKNOWN"})
                    self.transforms_dh.append({
                        "packet": packet_idx,
                        "dh_group": str(t_id),
                        "name": dh_info["name"],
                        "bits": dh_info["bits"],
                        "rating": dh_info.get("rating", "UNKNOWN")
                    })

                t_offset += t_len
                if t_last == 0:
                    pass

            offset += p_len
            if p_last == 0:
                break

    def _parse_ikev1_payload(self, packet_idx: int, p_type: int, body: bytes, evidence: Dict[str, Any]):
        """
        Parses IKEv1 Payloads (RFC 2409):
        p_type 1: SA
        p_type 2: Proposal
        p_type 3: Transform
        p_type 4: Key Exchange
        p_type 5: ID
        p_type 10: Nonce
        p_type 13: Vendor ID
        """
        if p_type == 1:  # SA payload
            # In IKEv1, SA has 4 bytes DOI, 4 bytes Situation, then Proposals
            if len(body) >= 12:
                # Basic check for proposals
                doi = struct.unpack("!I", body[:4])[0]
                evidence["ikev1_doi"] = doi
                # Parse proposal inside
                self._parse_ikev1_proposals(packet_idx, body[8:], evidence)
        elif p_type == 4:  # KE payload
            evidence["ikev1_ke_len"] = len(body)
            # Estimate DH group from public key length if not already parsed
            if len(body) == 96:
                dh_id = 1  # 768 bits
            elif len(body) == 128:
                dh_id = 2  # 1024 bits
            elif len(body) == 192:
                dh_id = 5  # 1536 bits
            elif len(body) == 256:
                dh_id = 14  # 2048 bits
            elif len(body) == 32:
                dh_id = 19  # 256-bit EC
            else:
                dh_id = None

            if dh_id and not any(d["dh_group"] == str(dh_id) for d in self.transforms_dh):
                dh_info = DH_GROUPS.get(dh_id, {"name": f"DH-Group-{dh_id}", "bits": 0, "rating": "UNKNOWN"})
                self.transforms_dh.append({
                    "packet": packet_idx,
                    "dh_group": str(dh_id),
                    "name": dh_info["name"],
                    "bits": dh_info["bits"],
                    "rating": dh_info.get("rating", "UNKNOWN")
                })

    def _parse_ikev1_proposals(self, packet_idx: int, data: bytes, evidence: Dict[str, Any]):
        """Parses IKEv1 proposal and transform payloads"""
        offset = 0
        while offset + 8 <= len(data):
            p_next, _, p_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack("!BBHBBBB", data[offset:offset + 8])
            if p_len < 8 or offset + p_len > len(data):
                break

            t_data = data[offset + 8 + spi_sz: offset + p_len]
            t_offset = 0
            while t_offset + 8 <= len(t_data):
                t_next, _, t_len, t_num, t_id, _ = struct.unpack("!BBHBBH", t_data[t_offset:t_offset + 8])
                if t_len < 8:
                    break

                # Parse IKEv1 Data Attributes:
                # 1: Encryption Algorithm (1=DES, 2=IDEA, 3=Blowfish, 4=RC5, 5=3DES, 7=AES-CBC)
                # 2: Hash Algorithm (1=MD5, 2=SHA1, 3=Tiger, 4=SHA2-256, 5=SHA2-384, 6=SHA2-512)
                # 3: Authentication Method (1=PSK, 2=DSS, 3=RSA-Sig, 4=RSA-Enc)
                # 4: Group Description (1=MODP-768, 2=MODP-1024, 5=MODP-1536, 14=MODP-2048)
                # 11: Life Type (1=seconds, 2=kilobytes)
                # 12: Life Duration
                # 14: Key Length
                attr_offset = 8
                encr_name = None
                hash_name = None
                dh_name = None
                dh_val = None
                life_sec = None

                while attr_offset + 4 <= t_len and t_offset + attr_offset + 4 <= len(t_data):
                    attr_type, attr_val = struct.unpack("!HH", t_data[t_offset + attr_offset: t_offset + attr_offset + 4])
                    if attr_type & 0x8000:
                        type_code = attr_type & 0x7FFF
                        if type_code == 1:
                            ikev1_enc = {1: "DES-CBC", 2: "IDEA-CBC", 3: "Blowfish-CBC", 5: "3DES-CBC", 7: "AES-CBC"}
                            encr_name = ikev1_enc.get(attr_val, f"ENCR_{attr_val}")
                        elif type_code == 2:
                            ikev1_hash = {1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "HMAC-SHA2-256", 5: "HMAC-SHA2-384", 6: "HMAC-SHA2-512"}
                            hash_name = ikev1_hash.get(attr_val, f"HASH_{attr_val}")
                        elif type_code == 4:
                            dh_val = attr_val
                            dh_entry = DH_GROUPS.get(attr_val, {"name": f"DH-Group-{attr_val}", "bits": 0, "rating": "UNKNOWN"})
                            dh_name = dh_entry["name"]
                        elif type_code == 12:
                            life_sec = attr_val
                    attr_offset += 4

                if encr_name:
                    self.transforms_encr.append({
                        "packet": packet_idx,
                        "name": encr_name,
                        "rating": "HIGH" if "DES" in encr_name else "MEDIUM"
                    })
                if hash_name:
                    self.transforms_integ.append({
                        "packet": packet_idx,
                        "name": hash_name,
                        "rating": "HIGH" if "MD5" in hash_name or "SHA1" in hash_name else "EXCELLENT"
                    })
                if dh_val:
                    dh_info = DH_GROUPS.get(dh_val, {"name": f"DH-Group-{dh_val}", "bits": 0, "rating": "UNKNOWN"})
                    self.transforms_dh.append({
                        "packet": packet_idx,
                        "dh_group": str(dh_val),
                        "name": dh_name,
                        "bits": dh_info["bits"],
                        "rating": dh_info.get("rating", "UNKNOWN")
                    })
                if life_sec:
                    self.observed_lifetimes.append(life_sec)

                t_offset += t_len
                if t_next == 0:
                    break

            offset += p_len
            if p_next == 0:
                break

    def get_summary(self) -> Dict[str, Any]:
        """Synthesizes IKE observations into fingerprint elements with evidence."""
        # Encryption
        encr = None
        encr_status = STATE_UNKNOWN
        if self.transforms_encr:
            encr = self.transforms_encr[0]["name"]
            encr_status = STATE_OBSERVED

        # Integrity
        integ = None
        integ_status = STATE_UNKNOWN
        if self.transforms_integ:
            integ = self.transforms_integ[0]["name"]
            integ_status = STATE_OBSERVED
        elif encr and ("GCM" in encr or "POLY1305" in encr):
            integ = "AEAD (Combined Mode)"
            integ_status = STATE_INFERRED

        # Diffie-Hellman
        dh_group = None
        dh_group_name = None
        dh_status = STATE_UNKNOWN
        if self.transforms_dh:
            dh_group = self.transforms_dh[0]["dh_group"]
            dh_group_name = self.transforms_dh[0]["name"]
            dh_status = STATE_OBSERVED

        # PFS (Perfect Forward Secrecy)
        # In IKEv2, PFS is active if CREATE_CHILD_SA contains a DH transform, or multiple KE payloads observed
        # If IKE exchange only has Phase 1 and no subsequent DH in Quick Mode / Child SA, PFS is either disabled or unobserved
        pfs = None
        pfs_status = STATE_UNKNOWN
        if len(self.transforms_dh) > 1:
            pfs = True
            pfs_status = STATE_OBSERVED
        elif self.transforms_dh and len(self.observed_exchanges) > 1:
            # If Child SA or Quick Mode occurred without DH transform, PFS is disabled
            child_or_qm = any("CREATE_CHILD_SA" in e or "Quick Mode" in e for e in self.observed_exchanges)
            if child_or_qm:
                pfs = False
                pfs_status = STATE_OBSERVED

        # Lifetime
        sa_lifetime = None
        lifetime_status = STATE_UNKNOWN
        if self.observed_lifetimes:
            sa_lifetime = self.observed_lifetimes[0]
            lifetime_status = STATE_OBSERVED

        return {
            "ike_version": self.observed_ike_version,
            "ike_version_status": STATE_OBSERVED if self.observed_ike_version else STATE_UNKNOWN,
            "encryption": encr,
            "encryption_status": encr_status,
            "integrity": integ,
            "integrity_status": integ_status,
            "dh_group": dh_group,
            "dh_group_name": dh_group_name,
            "dh_group_status": dh_status,
            "pfs": pfs,
            "pfs_status": pfs_status,
            "nat_traversal": self.nat_traversal_observed,
            "nat_traversal_status": STATE_OBSERVED if self.nat_traversal_observed else STATE_UNKNOWN,
            "sa_lifetime": sa_lifetime,
            "sa_lifetime_status": lifetime_status,
            "initiator_spi": self.initiator_spi,
            "responder_spi": self.responder_spi,
            "exchanges": self.observed_exchanges,
            "transforms_encr": self.transforms_encr,
            "transforms_integ": self.transforms_integ,
            "transforms_dh": self.transforms_dh,
            "evidence_count": len(self.evidence_log)
        }
