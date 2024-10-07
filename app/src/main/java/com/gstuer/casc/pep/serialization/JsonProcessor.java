package com.gstuer.casc.pep.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import org.pcap4j.packet.Packet;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class JsonProcessor {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    private final Gson gson;

    public JsonProcessor() {
        this(false);
    }

    public JsonProcessor(boolean prettyPrinting) {
        GsonBuilder builder = new GsonBuilder();
        if (prettyPrinting) {
            builder.setPrettyPrinting();
        }
        builder.registerTypeAdapter(Packet.class, new PacketSerializer());
        this.gson = builder.create();
    }

    public String convertToJson(Object object) throws SerializationException {
        try {
            return this.gson.toJson(object);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception.getCause());
        }
    }

    public <T> T convertToObject(String json, Class<T> objectClass) throws SerializationException {
        try {
            return this.gson.fromJson(json, objectClass);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception.getCause());
        }
    }

    public byte[] serialize(Object object) throws SerializationException {
        String json = convertToJson(object);
        return json.getBytes(DEFAULT_CHARSET);
    }

    public <T> T deserialize(byte[] object, Class<T> objectClass) throws SerializationException {
        String json = new String(object, DEFAULT_CHARSET);
        return this.convertToObject(json, objectClass);
    }
}
