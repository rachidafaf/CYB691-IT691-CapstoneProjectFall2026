"""
content_features.py — Step 7 request-time CONTENT features.

Reads from the NORMALIZED record's ``modbus.payload_parsed`` (what ml_detector
already sees), NOT raw eve.json — so it plugs straight into the ML pipeline.

Depends on log_parser.py emitting, for writes:
    payload_parsed = {"operation": "write", "address": <int>,
                      "quantity": <int>, "values": [<int>, ...]}
``decode_write_values`` below is the shared decoder the parser uses to produce
that ``values`` list from Suricata's eve.json ``request.write.data`` (which is a
clean int for FC5/FC6 and a lossy byte-string for FC15/FC16). Keeping the decoder
here means the parser and the feature extractor never disagree.

Features are OBSERVED content; the label (``authorized``) comes from the scenario
CSV, matched by timestamp — never from these fields (avoids data snooping).
See docs/content-anomaly-capture-spec.md.
"""
import re
import struct

# --- Legitimate HMI operating profile (Step 7 spec Section 3; prior knowledge) ---
HR_SETPOINT_MAP = set(range(0, 5))     # legitimate holding-register setpoints HR[0..4]
CO_ACTUATOR_MAP = set(range(0, 5))     # legitimate actuator coils CO[0..4]
REG_VALUE_BAND = (0, 1000)             # inclusive legitimate register value band

WRITE_FCS = {5, 6, 15, 16}
COIL_FCS = {5, 15}
REG_FCS = {6, 16}
READ_FCS = {1, 3}


# --- shared decoder (used by BOTH log_parser.py and the feature extractor) --------
def _data_to_bytes(s):
    """Reconstruct raw bytes from Suricata's write 'data' string, which mixes real
    characters (printable / already-decoded \\u escapes) with literal \\xHH escapes
    for non-printable bytes. Deterministic reverse of that representation."""
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        if (s[i] == "\\" and i + 4 <= n and s[i + 1] == "x"
                and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 2:i + 4])):
            out.append(int(s[i + 2:i + 4], 16))
            i += 4
        else:
            out.append(ord(s[i]) & 0xFF)
            i += 1
    return bytes(out)


def decode_write_values(function_raw, data):
    """Return (values: list[int], quantity) from eve.json request.write.data.
    FC6/FC5: data is an int (or int-as-string). FC16/FC15: raw byte payload."""
    if function_raw == 6:                                   # write single register
        return [int(data)], 1
    if function_raw == 5:                                   # write single coil (0xFF00/0x0000)
        return [1 if int(data) else 0], 1
    if function_raw == 16:                                  # write multiple registers (2 bytes/reg, BE)
        b = _data_to_bytes(str(data))
        nreg = len(b) // 2
        return list(struct.unpack(">" + "H" * nreg, b[:2 * nreg])), nreg
    if function_raw == 15:                                  # write multiple coils (bit-packed)
        b = _data_to_bytes(str(data))
        bits = [(b[i // 8] >> (i % 8)) & 1 for i in range(len(b) * 8)]
        return bits, len(bits)
    return [], 0


def _as_int(x):
    try:
        return int(str(x).strip())
    except (ValueError, TypeError):
        return None


# --- feature extraction from a normalized record's modbus object ------------------
def feature_row(modbus):
    """modbus = normalized_record['modbus']. Returns the content feature dict.
    Uses payload_parsed.values when present (preferred); falls back to the single
    'value' field so it still works before the parser patch lands."""
    fc = modbus.get("function_code")
    pp = modbus.get("payload_parsed", {}) or {}
    f = {
        "function_code": fc,
        "is_write": int(fc in WRITE_FCS) if fc is not None else 0,
        "write_address": _as_int(pp.get("address")),
        "quantity": _as_int(pp.get("quantity")),
        "value_max": None, "value_min": None,
        "address_in_map": None, "value_in_band": None,
    }
    if fc in WRITE_FCS:
        values = pp.get("values")
        if values is None:                                 # fallback: single 'value' field
            v = _as_int(pp.get("value"))
            values = [v] if v is not None else []
        amap = CO_ACTUATOR_MAP if fc in COIL_FCS else HR_SETPOINT_MAP
        if f["write_address"] is not None:                 # start-address in legitimate map
            f["address_in_map"] = int(f["write_address"] in amap)
        if fc in REG_FCS and values:
            f["value_max"], f["value_min"] = max(values), min(values)
            lo, hi = REG_VALUE_BAND
            f["value_in_band"] = int(all(lo <= v <= hi for v in values))
    return f


# --- static rule baselines (the DPI equivalents ML must beat on some class) -------
def rule_address_out_of_map(f):
    return int(f.get("address_in_map") == 0)               # A1 (oor_address), A5 (ro_write)


def rule_value_out_of_band(f):
    return int(f.get("value_in_band") == 0)                # A2, A3 (oor_value)


def rule_rate(inter_arrival_ms, threshold_ms=200):
    return int(inter_arrival_ms is not None and inter_arrival_ms < threshold_ms)  # A4 (burst)


if __name__ == "__main__":
    import json
    # representative NORMALIZED modbus objects (as ml_detector sees them)
    norm = {
        "A1 oor_address": {"function_code": 6, "payload_parsed": {"operation": "write", "address": 600, "value": "50"}},
        "A2 oor_value":   {"function_code": 6, "payload_parsed": {"operation": "write", "address": 2, "value": "65000"}},
        "A5 ro_write":    {"function_code": 6, "payload_parsed": {"operation": "write", "address": 20, "value": "10"}},
        # FC16 with the lossy value string straight out of normalized_telemetry.json:
        "A3 mixed (FC16)": {"function_code": 16, "payload_parsed": {"operation": "write", "address": 0,
                            "values": decode_write_values(16, "\x002\x00\x00\x00Z")[0]}},  # [50,0,90]-ish demo
        "C6 normal (FC16 lossy)": {"function_code": 16, "payload_parsed": {"operation": "write", "address": 2,
                            "values": decode_write_values(16, "\x00d\x00\\xc8\x01,")[0]}},   # -> [100,200,300]
        "C1 read":        {"function_code": 1, "payload_parsed": {"operation": "read", "address": 0, "quantity": 10}},
    }
    for name, rec in norm.items():
        print(f"{name:24} -> {json.dumps(feature_row(rec['modbus'] if 'modbus' in rec else rec))}")
    print("decode FC16 lossy  ->", decode_write_values(16, "\x00d\x00\\xc8\x01,"))