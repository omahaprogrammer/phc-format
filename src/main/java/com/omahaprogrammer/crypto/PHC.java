package com.omahaprogrammer.crypto;

import com.omahaprogrammer.crypto.function.PHCFunction;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PHC {
    private static final Pattern PATTERN = Pattern.compile("\\$(?<id>[a-z0-9-]*)(?:\\$([a-z0-9-]*)=([a-zA-Z0-9/+.-]*)(?:,([a-z0-9-]*)=([a-zA-Z0-9/+.-]*))*)?(?:\\$(?<salt>[a-zA-Z0-9/+.-]*)(?:\\$(?<hash>[a-zA-Z0-9/+.-]*))?)?");

    private final PHCFunction<?> function;
    private final NavigableMap<PHCFunction.Param<?, ?>, Object> params;
    private final byte[] salt;
    private final byte[] hashedPassword;

    private PHC(PHCFunction<?> function,
                  Map<PHCFunction.Param<?, ?>, Object> params,
                  byte[] salt,
                  byte[] hashedPassword) {
        this.function = function;
        this.params = Collections.unmodifiableNavigableMap(new TreeMap<>(params));
        this.salt = Arrays.copyOf(salt, salt.length);
        this.hashedPassword = Arrays.copyOf(hashedPassword, hashedPassword.length);
    }

    public static PHC parse(String hashString) {
        Matcher m = PATTERN.matcher(hashString);
        if (m.matches()) {
            var decoder = Base64.getDecoder();
            var id = m.group("id");
            var salt = decoder.decode(m.group("salt"));
            var hash = decoder.decode(m.group("hash"));
            var groups = m.groupCount() - 3;
            var params = new HashMap<String, String>();
            for (int i = 0; i < groups; i += 2) {
                params.put(m.group(i + 2), m.group(i + 3));
            }
            var fOpt = PHCFunction.getFunction(id);
            if (fOpt.isPresent()) {
                var function = fOpt.get();
                for (var entry : params.entrySet()) {

                }
            } else {
                throw new IllegalArgumentException("Unknown function");
            }
        }
        throw new IllegalArgumentException("Unparsable token");
    }

    public static <T extends PHCFunction<T>> Builder<T> builder(T function) {
        return new Builder<>(function);
    }

    public <T extends PHCFunction<T>> T getFunction() {
        return (T)function;
    }

    public <T extends PHCFunction<T>, V> V getParam(PHCFunction.Param<T, V> param) {
        return param.getValueClass().cast(params.get(param));
    }

    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }

    public byte[] getHashedPassword() {
        return Arrays.copyOf(hashedPassword, hashedPassword.length);
    }

    @Override
    public String toString() {
        var encoder = Base64.getEncoder().withoutPadding();
        var b = new StringBuilder();
        b.append('$').append(function.getId());

        var first = true;
        for (var entry : params.entrySet()) {
            var key = entry.getKey();
            var value = key.validate(entry.getKey());
            if (key.getName() != null) {
                if (first) {
                    b.append('$');
                } else {
                    b.append(',');
                }
                if (value instanceof byte[]) {
                    value = encoder.encodeToString((byte[])value);
                }
                b.append(key.getName()).append('=').append(value);
            }
        }
        b.append('$').append(encoder.encodeToString(salt));
        b.append('$').append(encoder.encodeToString(hashedPassword));
        return b.toString();
    }

    public static class Builder<T extends PHCFunction<T>> {
        private final T function;
        private NavigableMap<PHCFunction.Param<?, ?>, Object> params = new TreeMap<>();
        private byte[] salt;

        Builder(T function) {
            this.function = function;
        }

        public <V> Builder withParam(PHCFunction.Param<T, V> param, V value) {
            this.params.put(param, value);
            return this;
        }

        public Builder withSalt(byte[] salt) {
            if (this.salt != null) {
                throw new IllegalStateException("Salt already set");
            }
            this.salt = Arrays.copyOf(salt, salt.length);
            return this;
        }

        public Builder withRandomSalt(int sizeInBytes) {
            if (this.salt != null) {
                throw new IllegalStateException("Salt already set");
            }
            this.salt = new byte[sizeInBytes];
            new SecureRandom().nextBytes(salt);
            return this;
        }

        public PHC hash(char[] password) {
            if (salt == null) {
                throw new IllegalStateException("Salt is required");
            }

            var hash = function.hashPassword(params, salt, password);

            return new PHC(function, params, salt, hash);
        }
    }
}
