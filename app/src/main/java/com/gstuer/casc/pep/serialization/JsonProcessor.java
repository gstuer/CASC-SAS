package com.gstuer.casc.pep.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.gstuer.casc.pep.access.AccessControlMessage;
import com.gstuer.casc.pep.access.KeyExchangeMessage;
import com.gstuer.casc.pep.access.KeyExchangeRequestMessage;
import com.gstuer.casc.pep.access.PayloadExchangeMessage;
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

        // Enable pretty printing for debugging purposes
        if (prettyPrinting) {
            builder.setPrettyPrinting();
        }

        // Register custom type adapters to serialize/deserialize objects correctly
        builder.registerTypeAdapter(Packet.class, new PacketSerializer());
        RuntimeTypeAdapterFactory<?> messageAdapterFactory = RuntimeTypeAdapterFactory
                .of(AccessControlMessage.class)
                .registerSubtype(PayloadExchangeMessage.class)
                .registerSubtype(KeyExchangeMessage.class)
                .registerSubtype(KeyExchangeRequestMessage.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(messageAdapterFactory);
        this.gson = builder.create();
    }

    public static Charset getDefaultCharset() {
        return DEFAULT_CHARSET;
    }

    public String convertToJson(Object object) throws SerializationException {
        try {
            return this.gson.toJson(object);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
        }
    }

    public <T> T convertToObject(String json, Class<T> objectClass) throws SerializationException {
        try {
            return this.gson.fromJson(json, objectClass);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
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
