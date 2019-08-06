package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

abstract class Argon2<T extends Argon2<T>> extends PHCFunction<T> {
    private static final Map<String, Param<?, ?>> params = new HashMap<>();
    private static final int DEFAULT_SALT_LENGTH = 16;
    private static final int DEFAULT_HASH_LENGTH = 32;

    private final Integer type;
    Argon2(String id, Integer type) {
        super(id);
        this.type = type;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Optional<Param<T, ?>> getParam(String string) {
        return Optional.ofNullable((Param<T, ?>)params.get(string));
    }

    @Override
    public int getDefaultSaltLength() {
        return DEFAULT_SALT_LENGTH;
    }

    @Override
    public int getDefaultHashLength() {
        return DEFAULT_HASH_LENGTH;
    }

    @Override
    public byte[] hashPassword(Map<Param<?, ?>, ?> params, byte[] salt, char[] password, int length) {
        if (!params.keySet().containsAll(Set.of(
                MemorySizeParam.getInstance(),
                IterationsParam.getInstance(),
                ParallelismParam.getInstance()))) {
            throw new IllegalArgumentException("Required parameters are missing");
        }
        byte[] hash = new byte[length];

        var gen = new Argon2BytesGenerator();
        gen.init(new Argon2Parameters.Builder(type)
                .withMemoryAsKB(MemorySizeParam.getInstance().getValue(params))
                .withIterations(IterationsParam.getInstance().getValue(params))
                .withParallelism(ParallelismParam.getInstance().getValue(params))
                .withAdditional(DataParam.getInstance().getValue(params))
                .withSecret(KeyIdParam.getInstance().getValue(params))
                .withSalt(salt)
                .build());
        gen.generateBytes(password, hash);
        return hash;
    }

    public static final class MemorySizeParam<T extends Argon2<T>> extends Param<T, Integer> {
        private static final MemorySizeParam<?> INSTANCE = new MemorySizeParam<>();

        private MemorySizeParam() {
            super("m", 1, Integer.class);
            params.put("m", this);
        }

        protected void validateImpl(Integer val) {
            if (val < 1) {
                throw new IllegalArgumentException();
            }
        }

        @SuppressWarnings("unchecked")
        static <T extends Argon2<T>> MemorySizeParam<T> getInstance() {
            return (MemorySizeParam<T>) INSTANCE;
        }
    }

    public static final class IterationsParam<T extends Argon2<T>> extends Param<T, Integer> {
        private static final IterationsParam<?> INSTANCE = new IterationsParam<>();

        private IterationsParam() {
            super("t", 2, Integer.class);
            params.put("t", this);
        }

        protected void validateImpl(Integer val) {
            if (val < 1) {
                throw new IllegalArgumentException();
            }
        }

        @SuppressWarnings("unchecked")
        static <T extends Argon2<T>> IterationsParam<T> getInstance() {
            return (IterationsParam<T>) INSTANCE;
        }
    }

    public static final class ParallelismParam<T extends Argon2<T>> extends Param<T, Integer> {
        private static final ParallelismParam<?> INSTANCE = new ParallelismParam<>();

        private ParallelismParam() {
            super("p", 3, Integer.class);
            params.put("p", this);
        }

        protected void validateImpl(Integer val) {
            if (val < 1 || val > 255) {
                throw new IllegalArgumentException();
            }
        }

        @SuppressWarnings("unchecked")
        static <T extends Argon2<T>> ParallelismParam<T> getInstance() {
            return (ParallelismParam<T>) INSTANCE;
        }
    }

    public static final class KeyIdParam<T extends Argon2<T>> extends Param<T, byte[]> {
        private static final KeyIdParam<?> INSTANCE = new KeyIdParam<>();

        private KeyIdParam() {
            super("keyid", 4, byte[].class);
            params.put("keyid", this);
        }

        protected void validateImpl(byte[] val) {
            if (val.length > 8) {
                throw new IllegalArgumentException();
            }
        }

        @SuppressWarnings("unchecked")
        static <T extends Argon2<T>> KeyIdParam<T> getInstance() {
            return (KeyIdParam<T>) INSTANCE;
        }
    }

    public static final class DataParam<T extends Argon2<T>> extends Param<T, byte[]> {
        private static final DataParam<?> INSTANCE = new DataParam<>();

        private DataParam() {
            super("data",5, byte[].class);
            params.put("data", this);
        }

        protected void validateImpl(byte[] val) {
            if (val.length > 32) {
                throw new IllegalArgumentException();
            }
        }

        @SuppressWarnings("unchecked")
        static <T extends Argon2<T>> DataParam<T> getInstance() {
            return (DataParam<T>) INSTANCE;
        }
    }
}
