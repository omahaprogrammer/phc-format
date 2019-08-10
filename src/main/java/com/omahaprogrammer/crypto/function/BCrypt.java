package com.omahaprogrammer.crypto.function;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

public class BCrypt  extends PHCFunction<BCrypt> {
    public static final CostParam C = new CostParam();

    private static final BCrypt INSTANCE = new BCrypt();

    public static BCrypt getInstance() {
        return INSTANCE;
    }

    /**
     * Creates a new bcrypt function object
     */
    private BCrypt() {
        super("bcrypt");
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V> Optional<Param<BCrypt, V>> getParam(String paramId) {
        if (paramId.equals("c")) {
            return Optional.of((Param<BCrypt, V>) C);
        }
        return Optional.empty();
    }

    @Override
    public byte[] protectPassword(Map<Param<BCrypt, ?>, ?> params, byte[] salt, char[] password, int length) {
        if (!params.containsKey(C)) {
            throw new IllegalArgumentException("Required parameters missing");
        }
        if (salt.length != getDefaultSaltLength()) {
            throw new IllegalArgumentException("salt must be " + getDefaultSaltLength() + " bytes long");
        }
        if (length != getDefaultHashLength()) {
            throw new IllegalArgumentException("length must be " + getDefaultHashLength() + " bytes long");
        }
        var pwdbytes = org.bouncycastle.crypto.generators.BCrypt.passwordToByteArray(password);
        try {
            return org.bouncycastle.crypto.generators.BCrypt.generate(pwdbytes, salt, C.getValue(params));
        } finally {
            Arrays.fill(pwdbytes, (byte) 0);
        }
    }

    @Override
    public int getDefaultSaltLength() {
        return 16;
    }

    @Override
    public int getDefaultHashLength() {
        return 24;
    }

    public static final class CostParam extends Param<BCrypt, Integer> {
        private CostParam() {
            super("c", 1, Integer.class);
        }

        @Override
        protected void validateImpl(Integer value) {
            if (value < 4 || value > 31) {
                throw new IllegalArgumentException("cost must be between 4 and 31");
            }
        }
    }
}
