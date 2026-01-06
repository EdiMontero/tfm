-- INT (In-band Network Telemetry) Wireshark Dissector
-- Place this file in: %APPDATA%\Wireshark\plugins (Windows) or ~/.local/lib/wireshark/plugins (Linux)
-- or use: wireshark -X lua_script:int-dissector.lua

-- Create the protocol
int_proto = Proto("INT", "In-band Network Telemetry")

-- Define fields for INT Shim Header (6 bytes, network byte order)
local f_shim_type = ProtoField.uint8("int.shim.type", "Shim Type", base.DEC)
local f_shim_reserved = ProtoField.uint8("int.shim.reserved", "Shim Reserved", base.HEX)
local f_shim_length = ProtoField.uint16("int.shim.length", "Shim Length", base.DEC)
local f_shim_next_proto = ProtoField.uint16("int.shim.next_proto", "Next Protocol", base.HEX)

-- Define fields for INT Header (8 bytes, little-endian)
local f_hdr_version = ProtoField.uint8("int.header.version", "Version", base.DEC, nil, 0x0F)
local f_hdr_d = ProtoField.uint8("int.header.d", "D Flag", base.DEC, nil, 0x30)
local f_hdr_q = ProtoField.uint8("int.header.q", "Q Flag", base.DEC, nil, 0xC0)
local f_hdr_m = ProtoField.uint16("int.header.m", "M Flag", base.DEC, nil, 0x1F00)
local f_hdr_reserved1 = ProtoField.uint16("int.header.reserved1", "Reserved 1", base.HEX, nil, 0xE000)
local f_hdr_hop_ml = ProtoField.uint8("int.header.hop_ml", "Hop Metadata Length", base.DEC)
local f_hdr_instruction = ProtoField.uint16("int.header.instruction", "Instruction Bitmap", base.HEX)
local f_hdr_reserved2 = ProtoField.uint8("int.header.reserved2", "Reserved 2", base.HEX)
local f_hdr_remaining_hop = ProtoField.uint8("int.header.remaining_hop", "Remaining Hop Count", base.DEC)

-- Define fields for INT Metadata (32 bytes per hop, little-endian)
local f_md_switch_id = ProtoField.uint32("int.metadata.switch_id", "Switch ID", base.DEC)
local f_md_ingress_port = ProtoField.uint16("int.metadata.ingress_port", "Ingress Port ID", base.DEC)
local f_md_egress_port = ProtoField.uint16("int.metadata.egress_port", "Egress Port ID", base.DEC)
local f_md_hop_latency = ProtoField.uint32("int.metadata.hop_latency", "Hop Latency (µs)", base.DEC)
local f_md_queue_occupancy = ProtoField.uint32("int.metadata.queue_occupancy", "Queue Occupancy (packets)", base.DEC)
local f_md_ingress_ts = ProtoField.uint32("int.metadata.ingress_timestamp", "Ingress Timestamp (µs)", base.DEC)
local f_md_egress_ts = ProtoField.uint32("int.metadata.egress_timestamp", "Egress Timestamp (µs)", base.DEC)
local f_md_congestion = ProtoField.uint8("int.metadata.congestion", "Congestion Notification", base.HEX)
local f_md_reserved = ProtoField.bytes("int.metadata.reserved", "Reserved")

-- Register all fields
int_proto.fields = {
    f_shim_type, f_shim_reserved, f_shim_length, f_shim_next_proto,
    f_hdr_version, f_hdr_d, f_hdr_q, f_hdr_m, f_hdr_reserved1, f_hdr_hop_ml,
    f_hdr_instruction, f_hdr_reserved2, f_hdr_remaining_hop,
    f_md_switch_id, f_md_ingress_port, f_md_egress_port, f_md_hop_latency,
    f_md_queue_occupancy, f_md_ingress_ts, f_md_egress_ts, f_md_congestion, f_md_reserved
}

-- Dissector function
function int_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 14 then return end  -- Minimum packet size
    
    pinfo.cols.protocol = "INT"
    
    -- Add INT protocol tree
    local subtree = tree:add(int_proto, buffer(), "In-band Network Telemetry Data")
    
    local offset = 0
    
    -- Parse INT Shim Header (6 bytes, big-endian)
    if length < offset + 6 then return end
    
    local shim_tree = subtree:add(buffer(offset, 6), "INT Shim Header")
    shim_tree:add(f_shim_type, buffer(offset, 1))
    shim_tree:add(f_shim_reserved, buffer(offset + 1, 1))
    shim_tree:add(f_shim_length, buffer(offset + 2, 2))
    
    local shim_length = buffer(offset + 2, 2):uint()
    local next_proto = buffer(offset + 4, 2):uint()
    shim_tree:add(f_shim_next_proto, buffer(offset + 4, 2))
    
    offset = offset + 6
    
    -- Parse INT Header (8 bytes, little-endian)
    if length < offset + 8 then return end
    
    local hdr_tree = subtree:add(buffer(offset, 8), "INT Header")
    
    -- Parse first 4 bytes (little-endian)
    local word1 = buffer(offset, 4):le_uint()
    local version = bit.band(word1, 0x0F)
    local d = bit.band(bit.rshift(word1, 4), 0x03)
    local q = bit.band(bit.rshift(word1, 6), 0x03)
    local m = bit.band(bit.rshift(word1, 8), 0x1F)
    local reserved1 = bit.band(bit.rshift(word1, 13), 0x07)
    local hop_ml = bit.band(bit.rshift(word1, 16), 0xFF)
    
    hdr_tree:add(f_hdr_version, buffer(offset, 1)):append_text(" (" .. version .. ")")
    hdr_tree:add(f_hdr_d, buffer(offset, 1)):append_text(" (" .. d .. ")")
    hdr_tree:add(f_hdr_q, buffer(offset, 1)):append_text(" (" .. q .. ")")
    hdr_tree:add(f_hdr_m, buffer(offset, 2)):append_text(" (" .. m .. ")")
    hdr_tree:add(f_hdr_reserved1, buffer(offset, 2)):append_text(" (" .. reserved1 .. ")")
    hdr_tree:add(f_hdr_hop_ml, buffer(offset + 2, 1)):append_text(" (" .. hop_ml .. " blocks)")
    
    -- Parse second 4 bytes (little-endian)
    local word2 = buffer(offset + 4, 4):le_uint()
    local instruction = bit.band(word2, 0xFFFF)
    local reserved2 = bit.band(bit.rshift(word2, 16), 0xFF)
    local remaining_hop = bit.band(bit.rshift(word2, 24), 0xFF)
    
    hdr_tree:add(f_hdr_instruction, buffer(offset + 4, 2)):append_text(string.format(" (0x%04X)", instruction))
    hdr_tree:add(f_hdr_reserved2, buffer(offset + 6, 1))
    hdr_tree:add(f_hdr_remaining_hop, buffer(offset + 7, 1)):append_text(" (" .. remaining_hop .. " hops)")
    
    offset = offset + 8
    
    -- Calculate number of metadata blocks
    local num_blocks = hop_ml - remaining_hop
    
    if num_blocks < 0 then
        num_blocks = 0
    end
    
    subtree:append_text(", " .. num_blocks .. " metadata blocks")
    
    -- Parse INT Metadata blocks (32 bytes each, LITTLE-ENDIAN from BMv2)
    for i = 0, num_blocks - 1 do
        if length < offset + 32 then break end
        
        local md_tree = subtree:add(buffer(offset, 32), "INT Metadata Block " .. (i + 1) .. " (Hop " .. (i + 1) .. ")")
        
        -- Parse metadata fields (LITTLE-ENDIAN on x86 BMv2)
        -- padding(16) + switch_id(16)
        local padding = buffer(offset, 2):le_uint()
        local switch_id = buffer(offset + 2, 2):le_uint()
        md_tree:add_le(f_md_switch_id, buffer(offset + 2, 2)):append_text(" (SW" .. switch_id .. ")")
        
        local ingress_port = buffer(offset + 4, 2):le_uint()
        md_tree:add_le(f_md_ingress_port, buffer(offset + 4, 2))
        
        local egress_port = buffer(offset + 6, 2):le_uint()
        md_tree:add_le(f_md_egress_port, buffer(offset + 6, 2))
        
        local hop_latency = buffer(offset + 8, 4):le_uint()
        local hop_latency_ms = hop_latency / 1000.0
        md_tree:add_le(f_md_hop_latency, buffer(offset + 8, 4)):append_text(string.format(" (%.3f ms)", hop_latency_ms))
        
        local queue_occ = buffer(offset + 12, 4):le_uint()
        md_tree:add_le(f_md_queue_occupancy, buffer(offset + 12, 4))
        
        local ingress_ts = buffer(offset + 16, 4):le_uint()
        local ingress_ts_ms = ingress_ts / 1000.0
        md_tree:add_le(f_md_ingress_ts, buffer(offset + 16, 4)):append_text(string.format(" (%.3f ms)", ingress_ts_ms))
        
        local egress_ts = buffer(offset + 20, 4):le_uint()
        local egress_ts_ms = egress_ts / 1000.0
        md_tree:add_le(f_md_egress_ts, buffer(offset + 20, 4)):append_text(string.format(" (%.3f ms)", egress_ts_ms))
        
        md_tree:add(f_md_congestion, buffer(offset + 24, 1))
        md_tree:add(f_md_reserved, buffer(offset + 25, 7))
        
        -- Add summary to metadata tree
        if ingress_ts > 0 and egress_ts > 0 then
            local latency = egress_ts - ingress_ts
            local latency_ms = latency / 1000.0
            md_tree:append_text(string.format(" - Latency: %.3f ms", latency_ms))
        end
        
        offset = offset + 32
    end
    
    -- Calculate end-to-end latency if we have multiple blocks
    if num_blocks >= 2 then
        local first_ingress_ts = buffer(6 + 8 + 16, 4):le_uint()
        local last_egress_ts_offset = 6 + 8 + ((num_blocks - 1) * 32) + 20
        if length >= last_egress_ts_offset + 4 then
            local last_egress_ts = buffer(last_egress_ts_offset, 4):le_uint()
            if first_ingress_ts > 0 and last_egress_ts > 0 then
                local e2e_latency = last_egress_ts - first_ingress_ts
                local e2e_latency_ms = e2e_latency / 1000.0
                subtree:append_text(string.format(", E2E Latency: %.3f ms", e2e_latency_ms))
            end
        end
    end
    
    -- Parse encapsulated protocol if present
    if offset < length and next_proto == 0x0800 then
        -- IPv4 encapsulated
        local ip_dissector = Dissector.get("ip")
        if ip_dissector then
            ip_dissector:call(buffer(offset):tvb(), pinfo, tree)
        end
    elseif offset < length and next_proto ~= 0 then
        -- Try to dissect based on next_proto
        local eth_dissector = DissectorTable.get("ethertype")
        if eth_dissector then
            eth_dissector:try(next_proto, buffer(offset):tvb(), pinfo, tree)
        end
    end
end

-- Register the dissector
-- For EtherType 0x00FA (INT)
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x00FA, int_proto)

-- Also make dissector available for "Decode As" feature
-- This allows manual decoding of IEEE 802.3 frames
DissectorTable.get("wtap_encap"):add(wtap.USER0, int_proto)

print("INT dissector loaded successfully!")
print("INT packets with EtherType 0x00FA will be automatically dissected")
print("For IEEE 802.3 frames: Right-click packet -> Decode As -> INT")
