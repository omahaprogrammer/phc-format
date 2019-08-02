package com.omahaprogrammer.crypto;

import com.omahaprogrammer.crypto.function.PHCFunction;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class PHC {
    private final Map<String, Object> params;
    private final byte[] salt;
    private final byte[] hashedPassword;

    protected PHC(Map<String, Object> params,
                  byte[] salt,
                  byte[] hashedPassword) {
        this.params = Map.copyOf(params);
        this.salt = Arrays.copyOf(salt, salt.length);
        this.hashedPassword = Arrays.copyOf(hashedPassword, hashedPassword.length);
    }

    public static PHC parse(String hash) {
        return null;
    }

    public <T extends PHCFunction> Builder<T> builder(Class<T> clazz) {
        return new Builder<>();
    }

    public static class Builder<T extends PHCFunction> {
        private Map<String, Object> params = new HashMap<>();
        private byte[] salt;

        public Builder withParam(String param, Object value) {
            this.params.put(param, value);
            return this;
        }

        public Builder withSalt(byte[] salt) {
            this.salt = Arrays.copyOf(salt, salt.length);
            return this;
        }

        public Builder withRandomSalt(int sizeInBytes) {
            this.salt = new byte[sizeInBytes];
            new SecureRandom().nextBytes(salt);
            return this;
        }

        public PHC hash(char[] password) {
            return null;
        }
    }
}
