package com.omahaprogrammer.crypto;

import com.omahaprogrammer.crypto.function.*;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class PHC<T extends PHCFunction<T>> {
    private static final Map<String, PHCFunction<?>> functions;

    private static final Pattern TOKEN_PATTERN = Pattern.compile("\\$(?<id>[a-z0-9-]*)" +
            "(?:\\$(?<params>[a-z0-9-]*=[a-zA-Z0-9/+.-]*(?:,[a-z0-9-]*=[a-zA-Z0-9/+.-]*)*))?" +
            "(?:\\$(?<salt>[a-zA-Z0-9/+.-]*)(?:\\$(?<hash>[a-zA-Z0-9/+.-]*))?)?");

    private final T function;
    private final NavigableMap<PHCFunction.Param<?, ?>, Object> params;
    private final byte[] salt;
    private final byte[] hashedPassword;

    static {
        var funcs = List.of(
                Argon2i.getInstance(),
                Argon2d.getInstance(),
                Argon2id.getInstance(),
                PBKDF2.getInstance());
        functions = funcs.stream().collect(Collectors.toMap(PHCFunction::getId, e -> e));
    }

    private PHC(T function,
                  Map<PHCFunction.Param<?, ?>, Object> params,
                  byte[] salt,
                  byte[] hashedPassword) {
        this.function = function;
        this.params = Collections.unmodifiableNavigableMap(new TreeMap<>(params));
        this.salt = (salt == null) ? null : Arrays.copyOf(salt, salt.length);
        this.hashedPassword = (hashedPassword == null) ? null : Arrays.copyOf(hashedPassword, hashedPassword.length);
    }

    @SuppressWarnings("unchecked")
    private static <T extends PHCFunction<T>> Optional<T> getFunction(String id) {
        return Optional.ofNullable((T) functions.get(id));
    }

    public static <T extends PHCFunction<T>> PHC<T> parse(String hashString) {
        Matcher m = TOKEN_PATTERN.matcher(hashString);
        if (m.matches()) {
            var decoder = Base64.getDecoder();
            var id = m.group("id");
            var saltStr = m.group("salt");
            var hashStr = m.group("hash");
            var salt = (saltStr == null) ? null : decoder.decode(saltStr);
            var hash = (hashStr == null) ? null : decoder.decode(hashStr);
            var paramMap = extractParams(m);
            var fOpt = getFunction(id);
            if (fOpt.isPresent()) {
                var function = fOpt.get();
                var typedParams = new TreeMap<PHCFunction.Param<?, ?>, Object>();
                for (var entry : paramMap.entrySet()) {
                    var param = function.getParam(entry.getKey());
                    param.ifPresent(p -> typedParams.put(p, p.validate(entry.getValue())));
                }
                @SuppressWarnings("unchecked")
                PHC<T> phc = new PHC(function, typedParams, salt, hash);
                return phc;
            } else {
                throw new IllegalArgumentException("Unknown function");
            }
        }
        throw new IllegalArgumentException("Unparsable token");
    }

    private static Map<String, String> extractParams(Matcher m) {
        var params = m.group("params");
        var paramMap = new HashMap<String, String>();
        if (params != null) {
            var tuples = params.split(",");
            for (var tuple : tuples) {
                var parts = tuple.split("=");
                paramMap.put(parts[0], parts[1]);
            }
        }
        return paramMap;
    }

    public static <T extends PHCFunction<T>> Builder<T> builder(T function) {
        return new Builder<>(function);
    }

    public T getFunction() {
        return function;
    }

    public <V> V getParam(PHCFunction.Param<T, V> param) {
        return param.getValueClass().cast(params.get(param));
    }

    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }

    public byte[] getHashedPassword() {
        return Arrays.copyOf(hashedPassword, hashedPassword.length);
    }

    public boolean validate(char[] password) {
        var testhash = function.hashPassword(params, salt, password, hashedPassword.length);
        var valid = true;
        for (int i = hashedPassword.length - 1; i >= 0; --i) {
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

        public Builder<T> withRandomSalt() {
            return withRandomSalt(function.getDefaultSaltLength());
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
            return hash(password, function.getDefaultHashLength());
        }

        public PHC hash(char[] password, int hashLength) {
            if (salt == null) {
                throw new IllegalStateException("Salt is required");
            }

            var hash = function.hashPassword(params, salt, password, hashLength);

            return new PHC<>(function, params, salt, hash);
        }
    }
}
