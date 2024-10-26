package com.gstuer.casc.common.serialization;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;

import java.lang.reflect.Type;
import java.util.HexFormat;

public class PacketSerializer implements JsonSerializer<Packet>, JsonDeserializer<Packet> {
    private static final DataLinkType DEFAULT_DATA_LINK_TYPE = DataLinkType.EN10MB;

    @Override
    public JsonElement serialize(Packet src, Type typeOfSrc, JsonSerializationContext context) {
        HexFormat hexFormat = HexFormat.of();
        return new JsonPrimitive(hexFormat.formatHex(src.getRawData()));
    }

    @Override
    public Packet deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        String hexPacket = json.getAsString();
        byte[] rawPacket = HexFormat.of().parseHex(hexPacket);
        return PacketFactories.getFactory(Packet.class, DataLinkType.class)
                .newInstance(rawPacket, 0, rawPacket.length, DEFAULT_DATA_LINK_TYPE);
    }
}
