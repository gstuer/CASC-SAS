package com.gstuer.casc.pep.serialization;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import org.pcap4j.packet.Packet;

import java.lang.reflect.Type;
import java.util.HexFormat;

public class PacketSerializer implements JsonSerializer<Packet> {
    @Override
    public JsonElement serialize(Packet src, Type typeOfSrc, JsonSerializationContext context) {
        HexFormat hexFormat = HexFormat.of();
        return new JsonPrimitive(hexFormat.formatHex(src.getRawData()));
    }
}
