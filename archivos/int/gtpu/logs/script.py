from scapy.all import sniff
from influxdb import InfluxDBClient
import struct
import time
import binascii

# --- Configuration ---
IFACE = "ens4"
INFLUX_HOST = "localhost"
INFLUX_PORT = 8086
INFLUX_DB = "int_telemetry"

# --- Constants ---
# BMv2 timestamps are in MICROSECONDS (µs), not nanoseconds
US_TO_MS = 1000.0  # 1 ms = 1,000 µs

# --- Connect to InfluxDB ---
client = InfluxDBClient(host=INFLUX_HOST, port=INFLUX_PORT, database=INFLUX_DB)

def parse_int_metadata_correct(md_data, hop_number):
    """
    Parse one INT metadata block (32 bytes).

    IMPORTANT:
    - In this project, INT-MD fields are emitted in network byte order (big-endian).
    - Offsets must match the P4 `int_md_t` layout exactly.
    """
   
    if len(md_data) < 32:
        print(f"[ERROR] Metadata block too short: {len(md_data)} bytes")
        return None
   
    try:
        # INT-MD on the wire is network byte order (big-endian)
        padding = struct.unpack('>H', md_data[0:2])[0]
        switch_id = struct.unpack('>H', md_data[2:4])[0]
        ingress_port_id = struct.unpack('>H', md_data[4:6])[0]
        egress_port_id = struct.unpack('>H', md_data[6:8])[0]

        hop_latency_field = struct.unpack('>I', md_data[8:12])[0]
        queue_occupancy = struct.unpack('>I', md_data[12:16])[0]
        ingress_timestamp = struct.unpack('>I', md_data[16:20])[0]
        egress_timestamp = struct.unpack('>I', md_data[20:24])[0]

        congestion_notification = md_data[24]

        # Prefer deriving latency from timestamps if present (wrap-safe).
        ts_latency = None
        if ingress_timestamp != 0 and egress_timestamp != 0:
            ts_latency = (egress_timestamp - ingress_timestamp) & 0xFFFFFFFF

        # Heuristic recovery for a common failure mode seen on some hops:
        # - hop_latency_field == 0
        # - egress_timestamp == 0
        # - queue_occupancy looks like a timestamp close to ingress_timestamp
        # This typically indicates the hop didn't populate all fields consistently.
        recovered = False
        if (
            hop_latency_field == 0
            and egress_timestamp == 0
            and ingress_timestamp > 1_000_000
            and queue_occupancy > 1_000_000
        ):
            candidate_delta = (ingress_timestamp - queue_occupancy) & 0xFFFFFFFF
            # If the two values are close (sub-second), treat them as (ingress_ts, egress_ts).
            if candidate_delta < 1_000_000:
                ingress_timestamp, egress_timestamp = queue_occupancy, ingress_timestamp
                queue_occupancy = 0
                ts_latency = (egress_timestamp - ingress_timestamp) & 0xFFFFFFFF
                recovered = True

        hop_latency_used = ts_latency if ts_latency is not None else hop_latency_field

        hop_latency_ms = hop_latency_used / US_TO_MS
        ingress_timestamp_ms = ingress_timestamp / US_TO_MS
        egress_timestamp_ms = egress_timestamp / US_TO_MS

        flags = []
        if ts_latency is not None:
            flags.append("ts")
        if recovered:
            flags.append("recovered")
        if queue_occupancy > 1_000_000:
            flags.append("queue_suspicious")

        flags_str = f" [{'|'.join(flags)}]" if flags else ""

        print(
            f"[DEBUG] Hop {hop_number}: switch={switch_id}, "
            f"ingress={ingress_port_id}, egress={egress_port_id}, "
            f"queue={queue_occupancy} packets, "
            f"ingress_ts={ingress_timestamp_ms:.3f}ms, egress_ts={egress_timestamp_ms:.3f}ms, "
            f"latency={hop_latency_ms:.3f}ms ({hop_latency_used}µs){flags_str}"
        )

        return {
            "switch_id": switch_id,
            "ingress_port_id": ingress_port_id,
            "egress_port_id": egress_port_id,
            "hop_latency": hop_latency_used,
            "hop_latency_ms": hop_latency_ms,
            "queue_occupancy": queue_occupancy,
            "ingress_timestamp": ingress_timestamp,
            "ingress_timestamp_ms": ingress_timestamp_ms,
            "egress_timestamp": egress_timestamp,
            "egress_timestamp_ms": egress_timestamp_ms,
            "congestion_notification": congestion_notification,
            "hop_number": hop_number,
            "hop_latency_field": hop_latency_field,
        }
       
    except Exception as e:
        print(f"[ERROR] Metadata parsing failed for hop {hop_number}: {e}")
        print(f"[DEBUG] Raw metadata hex: {binascii.hexlify(md_data).decode()}")
        return None

def parse_int_packet(pkt):
    """Parse INT packet from raw L2 bytes.

    Note: INT uses a custom 'etherType' value 0x00FA which is < 0x0600.
    Many tools classify it as IEEE 802.3 length, so we must parse bytes directly.
    """

    raw_data = bytes(pkt)
    if len(raw_data) < 14:
        return None

    dst_mac = ':'.join(f"{b:02x}" for b in raw_data[0:6])
    src_mac = ':'.join(f"{b:02x}" for b in raw_data[6:12])
    type_or_len = struct.unpack('>H', raw_data[12:14])[0]

    print(f"\n[INT] New packet: {src_mac} -> {dst_mac}, length: {len(raw_data)} bytes")
   
    if type_or_len != 0x00FA:
        return None

    offset = 14

    # Basic sanity: INT shim type is expected to be 1
    if len(raw_data) < offset + 1:
        return None
    print(f"[DEBUG] First payload byte: 0x{raw_data[offset]:02x}")
   
    try:
        # Parse INT Shim Header (6 bytes) - network byte order (big-endian)
        if len(raw_data) < offset + 6:
            return None
           
        shim_data = raw_data[offset:offset+6]
        shim_type, shim_reserved, shim_length, shim_next_proto = struct.unpack('>BBHH', shim_data)
        print(f"[INT] Shim: type={shim_type}, length={shim_length}, next_proto=0x{shim_next_proto:04x}")
        offset += 6
       
        # Parse INT Header.
        # IMPORTANT: In your P4, `int_header_t` is 56 bits (7 bytes), not 8 bytes.
        # Layout:
        #   version(4) | d(2) | q(2)
        #   m(5) | reserved1(3)
        #   hop_ml(8)
        #   instruction(16)
        #   reserved2(8)
        #   remaining_hop_cnt(8)
        INT_HEADER_LEN = 7
        if len(raw_data) < offset + INT_HEADER_LEN:
            return None
           
        header_data = raw_data[offset:offset+INT_HEADER_LEN]
        print(f"[DEBUG] Raw INT header (hex): {binascii.hexlify(header_data).decode()}")

        b0 = header_data[0]
        b1 = header_data[1]
        version = (b0 >> 4) & 0x0F
        d = (b0 >> 2) & 0x03
        q = b0 & 0x03
        m = (b1 >> 3) & 0x1F
        reserved1 = b1 & 0x07
        hop_ml = header_data[2]
        instruction = struct.unpack('>H', header_data[3:5])[0]
        reserved2 = header_data[5]
        remaining_hop_cnt = header_data[6]
       
        print(f"[INT] Header: version={version}, d={d}, q={q}, m={m}, hop_ml={hop_ml}, "
              f"instruction=0x{instruction:04x}, remaining_hops={remaining_hop_cnt}")

        offset += INT_HEADER_LEN

        # Compute number of 32-byte metadata blocks from shim.length.
        # In this project, SW1 sets shim.length = 12 + 32*N and each hop increases it by 32.
        # (12 bytes is a logical overhead used by the P4 program; it does not need to match
        #  the on-wire shim/header sizes exactly, but it makes hop counting consistent.)
        base_overhead = 12
        if shim_length < base_overhead:
            num_blocks = 0
        else:
            num_blocks = (shim_length - base_overhead) // 32

        if num_blocks < 0:
            num_blocks = 0
        if num_blocks > 8:
            num_blocks = 8
       
        print(f"[INT] Extracting {num_blocks} metadata blocks (hop_ml={hop_ml}, remaining={remaining_hop_cnt})")
       
        # Extract metadata blocks
        metadata_blocks = []
        for i in range(num_blocks):
            if len(raw_data) < offset + 32:
                print(f"[WARNING] Not enough data for metadata block {i+1}")
                break
               
            md_block_data = raw_data[offset:offset+32]
            print(f"[DEBUG] Metadata block {i+1} (hex): {binascii.hexlify(md_block_data).decode()}")
           
            md_info = parse_int_metadata_correct(md_block_data, i + 1)
            if md_info:
                metadata_blocks.append(md_info)

            offset += 32
           
        # Calculate actual hop latency from timestamps if available
            if md_info:
                print(
                    f" Switch {md_info['switch_id']} (Hop {md_info['hop_number']}): "
                    f"Port {md_info['ingress_port_id']}->{md_info['egress_port_id']}, "
                    f"Latency {md_info['hop_latency_ms']:.3f}ms ({md_info['hop_latency']}µs), "
                    f"Queue {md_info['queue_occupancy']} packets"
                )
       
        # End-to-end latency:
        # Do NOT subtract timestamps across different switches unless clocks are synchronized.
        # In BMv2 each switch instance has its own timestamp domain, so cross-switch subtraction
        # can be negative or meaningless. Use the sum of per-hop latencies instead.
        if len(metadata_blocks) >= 1:
            e2e_latency_us = sum(md["hop_latency"] for md in metadata_blocks)
            e2e_latency_ms = e2e_latency_us / US_TO_MS
            print(f" END-TO-END LATENCY (sum of hops): {e2e_latency_ms:.3f}ms ({e2e_latency_us}µs)")
       
        return metadata_blocks
       
    except Exception as e:
        print(f"[ERROR] Packet parsing failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def handle_packet(pkt):
    """Handle incoming packets"""
    try:
        print("=" * 80)
        metadata_blocks = parse_int_packet(pkt)
       
        if not metadata_blocks:
            print("No valid INT metadata found")
            return
       
        print(f" Processing {len(metadata_blocks)} metadata blocks")
       
        # Store path information
        switch_ids = [f"SW{md['switch_id']}" for md in metadata_blocks]
        path_str = " -> ".join(switch_ids)
        print(f" PATH: {path_str}")
       
        # Send each block to InfluxDB
        for md_block in metadata_blocks:
            # Calculate actual latency from timestamps if available
            if md_block["ingress_timestamp"] > 0 and md_block["egress_timestamp"] > 0:
                actual_latency = md_block["egress_timestamp"] - md_block["ingress_timestamp"]
                actual_latency_ms = actual_latency / US_TO_MS  # Convert µs to ms
            else:
                actual_latency = md_block["hop_latency"]
                actual_latency_ms = actual_latency / US_TO_MS  # Convert µs to ms
           
            # Send both µs and ms to database for flexibility
            json_body = [{
                "measurement": "int_metrics",
                "tags": {
                    "switch_id": md_block["switch_id"],
                    "ingress_port": md_block["ingress_port_id"],
                    "egress_port": md_block["egress_port_id"],
                    "hop_number": md_block["hop_number"],
                    "path_position": f"hop_{md_block['hop_number']}"
                },
                "fields": {
                    # Latency in microseconds (original)
                    "hop_latency_us": actual_latency,
                    # Latency in milliseconds (converted)
                    "hop_latency_ms": actual_latency_ms,
                    # Queue occupancy in packets (not time!)
                    "queue_occupancy_packets": md_block["queue_occupancy"],
                    # Timestamps in microseconds
                    "ingress_timestamp_us": md_block["ingress_timestamp"],
                    "egress_timestamp_us": md_block["egress_timestamp"],
                    # Timestamps in milliseconds
                    "ingress_timestamp_ms": md_block["ingress_timestamp_ms"],
                    "egress_timestamp_ms": md_block["egress_timestamp_ms"],
                    "congestion_notification": md_block["congestion_notification"],
                    "switch_id_num": md_block["switch_id"]
                },
                "time": int(time.time() * 1e9)
            }]
           
            try:
                client.write_points(json_body)
                print(f" Saved to DB: Switch {md_block['switch_id']}, Hop {md_block['hop_number']}, "
                      f"Latency: {actual_latency_ms:.3f}ms")
            except Exception as e:
                print(f" DB Error: {e}")
       
        # Store aggregated path information (sum of per-hop latencies)
        if len(metadata_blocks) >= 1:
            e2e_latency_us = sum(md["hop_latency"] for md in metadata_blocks)
            e2e_latency_ms = e2e_latency_us / US_TO_MS

            first_hop = metadata_blocks[0]
            last_hop = metadata_blocks[-1]

            path_json_body = [{
                "measurement": "int_path_metrics",
                "tags": {
                    "path": path_str,
                    "hop_count": len(metadata_blocks)
                },
                "fields": {
                    "end_to_end_latency_us": e2e_latency_us,
                    "end_to_end_latency_ms": e2e_latency_ms,
                    "total_hops": len(metadata_blocks),
                    "first_switch": first_hop["switch_id"],
                    "last_switch": last_hop["switch_id"],
                },
                "time": int(time.time() * 1e9)
            }]

            try:
                client.write_points(path_json_body)
                print(f" Saved path to DB: {path_str}, E2E latency (sum): {e2e_latency_ms:.3f}ms ({e2e_latency_us}µs)")
            except Exception as e:
                print(f" Path DB Error: {e}")
               
    except Exception as e:
        print(f" Packet handling failed: {e}")
        import traceback
        traceback.print_exc()

def test_influxdb():
    """Test InfluxDB connection"""
    try:
        client.ping()
        print("InfluxDB: Connected ✓")
       
        # Create database if it doesn't exist
        databases = client.get_list_database()
        if not any(db['name'] == INFLUX_DB for db in databases):
            client.create_database(INFLUX_DB)
            print(f"Created database: {INFLUX_DB}")
           
        return True
    except Exception as e:
        print(f"InfluxDB connection failed: {e}")
        return False

def main():
    print("=== INT Telemetry Report Server ===")
    print("MULTI-HOP FIXED VERSION - WITH MS CONVERSION")
    print(f"Conversion factor: 1 ms = {US_TO_MS:,.0f} µs")
    print("=" * 50)
   
    if not test_influxdb():
        return
   
    print(f"Listening on interface: {IFACE}")
    print("Waiting for INT telemetry packets...")
    print("Press Ctrl+C to stop\n")
   
    try:
        sniff(iface=IFACE, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n Stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()



