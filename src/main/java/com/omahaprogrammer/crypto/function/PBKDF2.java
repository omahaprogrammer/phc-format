package com.omahaprogrammer.crypto.function;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class PBKDF2 extends PHCFunction<PBKDF2> {
    public static final AlgorithmParam ALGORITHM = new AlgorithmParam();
    public static final IterationsParam ITERATIONS = new IterationsParam();

    static final Map<String, Param<PBKDF2, ?>> params = new HashMap<>();

    public PBKDF2() {
        super("pbkdf2");
    }

    @Override
    public Optional<Param<PBKDF2, ?>> getParam(String string) {
        return Optional.ofNullable(params.get(string));
    }

    @Override
    public byte[] hashPassword(Map<Param<?, ?>, ?> params, byte[] salt, char[] password) {
        return new byte[0];
    }

    public enum Algorithm {
        HMAC_SHA1("HmacSHA1"),
        HMAC_SHA1_AND_UTF8("HmacSHA1AndUTF8"),
        HMAC_SHA1_AND_8BIT("HmacSHA1And8bit"),
        HMAC_SHA224("HmacSHA224"),
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA384("HmacSHA384"),
        HMAC_SHA512("HmacSHA512"),
        HMAC_SHA3_224("HmacSHA3_224"),
        HMAC_SHA3_256("HmacSHA3_256"),
        HMAC_SHA3_384("HmacSHA3_384"),
        HMAC_SHA3_512("HmacSHA3_512");

        private final String label;

        Algorithm(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    public static final class AlgorithmParam extends Param<PBKDF2, Algorithm> {
        private AlgorithmParam() {
            super("alg", 1, Algorithm.class);
            params.put("alg", this);
        }

        @Override
        protected void validateImpl(Algorithm value) {

        }
    }

    public static final class IterationsParam extends Param<PBKDF2, Integer> {
        private IterationsParam() {
            super("t", 2, Integer.class);
            params.put("t", this);
        }

        protected void validateImpl(Integer val) {
            if (val < 1) {
                throw new IllegalArgumentException();
            }
        }
    }

    public static final class HashLengthParam extends Param<PBKDF2, Integer> {
        private HashLengthParam() {
            super (null, Integer.MAX_VALUE, Integer.class);
        }

        protected void validateImpl(Integer val) {
            if (val < 12 || val > 64) {
                throw new IllegalArgumentException();
            }
        }
    }
}
