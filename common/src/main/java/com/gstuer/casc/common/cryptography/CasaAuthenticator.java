package com.gstuer.casc.common.cryptography;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.apache.commons.lang3.RandomUtils;

import java.io.Serial;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.function.Function;

public class CasaAuthenticator extends Authenticator<CasaAuthenticator.SecretKey, CasaAuthenticator.PublicKey> {
    public static final String ALGORITHM_IDENTIFIER = "S_CASA";
    // TODO Move to CAPP
    private final Element s;
    private final Element g2;

    private final byte[] identity;
    private final MessageDigest hash;
    private final Pairing pairing;
    private final Function<byte[], Element> H1;
    private final Function<byte[], Element> H2;
    private final Function<Element, Element> H3;

    public CasaAuthenticator() {
        this(RandomUtils.insecure().randomBytes(128));
    }

    public CasaAuthenticator(byte[] identity) {
        this.identity = identity;
        // Initialize pairing
        int rBits = 160;
        int qBits = 512;
        // TODO Move attributes to CAPP
        //PairingParametersGenerator<?> parameterGenerator = new TypeACurveGenerator(rBits, qBits);
        //PairingFactory.getInstance().setUsePBCWhenPossible(true);
        //PairingParameters parameters = parameterGenerator.generate();
        PropertiesParameters parameters = new PropertiesParameters();
        parameters.put("type", "a");
        parameters.put("q", "4836892851346756270672474216557936496011836796236357672079815466346872124608160298966679189414445070142886793957275599622482693170691571254335692659634559");
        parameters.put("r", "730750818665451459101842416367364881864821047297");
        parameters.put("h", "6619072778023335216623131162590980170104064630160038593128865618384224932378724958969151858161129853956480");
        parameters.put("exp1", "63");
        parameters.put("exp2", "159");
        parameters.put("sign0", "1");
        parameters.put("sign1", "1");
        this.pairing = PairingFactory.getPairing(parameters);

        // Initialize hashes
        try {
            this.hash = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException exception) {
            // Since the algorithm is static, this exception might only be thrown in case of an incompatible platform
            throw new UnsupportedOperationException(exception);
        }
        // H1: {0,1}* -> G1
        this.H1 = (bytes) -> {
            byte[] hash = this.hash.digest(bytes);
            return this.pairing.getG1().newElementFromHash(hash, 0, hash.length).getImmutable();
        };
        // H2: {0,1}* -> Z_q*
        this.H2 = (bytes) -> {
            byte[] hash = this.hash.digest(bytes);
            return this.pairing.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        };
        // H3: Z_q* -> G2
        this.H3 = (element) -> {
            byte[] hash = this.hash.digest(element.toBytes());
            return this.pairing.getG2().newElementFromHash(hash, 0, hash.length).getImmutable();
        };

        // Initialize CAPP attributes
        // TODO Move to CAPP
        byte[] sHash = hash.digest("ValuesS".getBytes());
        this.s = pairing.getZr().newElementFromHash(sHash, 0, sHash.length).getImmutable();
        //this.s = pairing.getZr().newRandomElement().getImmutable();
        byte[] g2Hash = hash.digest("ValuesG2".getBytes());
        this.g2 = pairing.getG2().newElementFromHash(g2Hash, 0, g2Hash.length).getImmutable();
        //this.g2 = pairing.getG2().newRandomElement().getImmutable();
    }

    @Override
    public void initializeKeyPair() {
        // Partial private key generation
        // TODO Move to CAPP
        Element ppk = H1.apply(identity).powZn(s).getImmutable();

        // Private key generation @ PEP
        Element x = pairing.getZr().newRandomElement().getImmutable();
        this.setSigningKey(new SecretKey(ppk, x));

        // TODO Replace with ppkAgg from CAPP
        this.setVerificationKey(new PublicKey(ppk));
    }

    @Override
    public DigitalSignature sign(byte[] data) {
        Element x = this.getSigningKey().getX();
        Element ppk = this.getSigningKey().getPpk();
        Element h = H2.apply(data);
        Element signature = ppk.mul(H3.apply(h).powZn(x)).getImmutable();
        return new DigitalSignature(signature.toBytes(), this.getAlgorithmIdentifier());
    }

    @Override
    public boolean verify(byte[] data, DigitalSignature signature) {
        // Server-Aided Verification
        // TODO Move to CAPP
        // TODO Calculate product of all devices
        Element pk_agg = this.getVerificationKey().getPkAgg();
        Element signatureCurveElement = pairing.getG1().newElementFromBytes(signature.getData());
        Element eServer = pairing.pairing(signatureCurveElement, g2);

        // Entity Verification
        Element eEntity = pairing.pairing(pk_agg.mul(signatureCurveElement.div(pk_agg)), g2);
        return eServer.isEqual(eEntity);
    }

    @Override
    public void setVerificationKey(EncodedKey encodedVerificationKey) {
        this.setVerificationKey(new PublicKey(encodedVerificationKey));
    }

    @Override
    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }

    public static class SecretKey implements Key {
        @Serial
        private static final long serialVersionUID = 3301246079826707923L;

        private final Element ppk;
        private final Element x;

        public SecretKey(Element ppk, Element x) {
            this.ppk = Objects.requireNonNull(ppk);
            this.x = Objects.requireNonNull(x);
        }

        public Element getPpk() {
            return ppk;
        }

        public Element getX() {
            return x;
        }

        @Override
        public String getAlgorithm() {
            return ALGORITHM_IDENTIFIER;
        }

        @Override
        public String getFormat() {
            return "RawBytes";
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    public class PublicKey implements Key {
        @Serial
        private static final long serialVersionUID = 3301246079826707923L;

        private final Element pkAgg;

        public PublicKey(EncodedKey encodedKey) {
            // TODO Add check if algorithm is correct
            this.pkAgg = pairing.getG1().newElementFromBytes(encodedKey.getKey());
        }

        public PublicKey(Element pkAgg) {
            this.pkAgg = Objects.requireNonNull(pkAgg);
        }

        public Element getPkAgg() {
            return pkAgg;
        }

        @Override
        public String getAlgorithm() {
            return ALGORITHM_IDENTIFIER;
        }

        @Override
        public String getFormat() {
            return "RawBytes";
        }

        @Override
        public byte[] getEncoded() {
            return this.pkAgg.toBytes();
        }
    }
}
