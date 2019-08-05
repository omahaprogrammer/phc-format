package com.omahaprogrammer.crypto;

import com.omahaprogrammer.crypto.function.PHCFunction;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PHC {
    private static final Pattern TOKEN_PATTERN = Pattern.compile("\\$(?<id>[a-z0-9-]*)" +
            "(?:\\$(?<params>[a-z0-9-]*=[a-zA-Z0-9/+.-]*(?:,[a-z0-9-]*=[a-zA-Z0-9/+.-]*)*))?" +
            "(?:\\$(?<salt>[a-zA-Z0-9/+.-]*)(?:\\$(?<hash>[a-zA-Z0-9/+.-]*))?)?");

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
        this.salt = (salt == null) ? null : Arrays.copyOf(salt, salt.length);
        this.hashedPassword = (hashedPassword == null) ? null : Arrays.copyOf(hashedPassword, hashedPassword.length);
    }

    public static PHC parse(String hashString) {
        Matcher m = TOKEN_PATTERN.matcher(hashString);
        if (m.matches()) {
            var decoder = Base64.getDecoder();
            var id = m.group("id");
            var saltStr = m.group("salt");
            var hashStr = m.group("hash");
            var salt = (saltStr == null) ? null : decoder.decode(saltStr);
            var hash = (hashStr == null) ? null : decoder.decode(hashStr);
            var params = m.group("params");
            var paramMap = new HashMap<String, String>();
            if (params != null) {
                var tuples = params.split(",");
                for (var tuple : tuples) {
                    var parts = tuple.split("=");
                    paramMap.put(parts[0], parts[1]);
                }
            }
            var fOpt = PHCFunction.getFunction(id);
            if (fOpt.isPresent()) {
                var function = fOpt.get();
                var typedParams = new TreeMap<PHCFunction.Param<?, ?>, Object>();
                for (var entry : paramMap.entrySet()) {
                    var param = function.getParam(entry.getKey());
                    param.ifPresent(p -> typedParams.put(p, p.validate(entry.getValue())));
                }
                return new PHC(function, typedParams, salt, hash);
            } else {
                throw new IllegalArgumentException("Unknown function");
            }
        }
        throw new IllegalArgumentException("Unparsable token");
    }

    public static <T extends PHCFunction<T>> Builder<T> builder(T function) {
        return new Builder<>(function);
    }

    @SuppressWarnings("unchecked")
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

    public boolean validate(char[] password) {
        var testhash = function.hashPassword(params, salt, password);
        var valid = testhash.length == hashedPassword.length;
        for (int i = Integer.min(testhash.length, hashedPassword.length) - 1; i >= 0; --i) {
            valid &= testhash[i] == hashedPassword[i];
        }
        return valid;
    }

    @Override
    public String toString() {
        var encoder = Base64.getEncoder().withoutPadding();
        var b = new StringBuilder();
        b.append('$').append(function.getId());

        var first = true;
        for (var entry : params.entrySet()) {
            var key = entry.getKey();
            var value = key.validate(entry.getValue());
            if (key.getName() != null) {
                if (first) {
                    b.append('$');
                    first = false;
                } else {
                    b.append(',');
                }
                if (value instanceof byte[]) {
                    value = encoder.encodeToString((byte[])value);
                }
                b.append(key.getName()).append('=').append(value);
            }
        }
        if (salt != null) {
            b.append('$').append(encoder.encodeToString(salt));
            if (hashedPassword != null) {
                b.append('$').append(encoder.encodeToString(hashedPassword));
            }
        }
        return b.toString();
    }

    public static class Builder<T extends PHCFunction<T>> {
        private final T function;
        private NavigableMap<PHCFunction.Param<?, ?>, Object> params = new TreeMap<>();
        private byte[] salt;

        Builder(T function) {
            this.function = function;
        }

        public <V> Builder<T> withParam(PHCFunction.Param<T, V> param, V value) {
            this.params.put(param, value);
            return this;
        }

        public Builder<T> withSalt(byte[] salt) {
            if (this.salt != null) {
                throw new IllegalStateException("Salt already set");
            }
            this.salt = Arrays.copyOf(salt, salt.length);
            return this;
        }

        public Builder<T> withRandomSalt(int sizeInBytes) {
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
