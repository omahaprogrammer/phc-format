package com.omahaprogrammer.crypto.function;

import java.util.Set;

public class Argon2d extends PHCFunction {

    public Argon2d() {
        super("argon2d");
    }

    @Override
    public byte[] hashPassword(Set<Param<?>> params, char[] password) {
        return new byte[0];
    }

    public static final class MemorySizeParam extends Param<Integer> {
        private MemorySizeParam(Integer value) {
            super("m", value);
        }

        public static MemorySizeParam of(Integer value) {
            if (value < 1) {
                throw new IllegalArgumentException("value must be at least 1");
            }
            return new MemorySizeParam(value);
        }
    }

    public static final class IterationsParam extends Param<Integer> {
        private IterationsParam(Integer value) {
            super("t", value);
        }

        public static IterationsParam of(Integer value) {
            if (value < 1) {
                throw new IllegalArgumentException("value must be at least 1");
            }
            return new IterationsParam(value);
        }
    }

    public static final class ParallelismParam extends Param<Integer> {
        private ParallelismParam(Integer value) {
            super("p", value);
        }

        public static ParallelismParam of(Integer value) {
            if (value < 1 || value > 255) {
                throw new IllegalArgumentException("value must be between 1 and 255");
            }
            return new ParallelismParam(value);
        }
    }

    public static final class KeyIdParam extends Param<byte[]> {
        private KeyIdParam(byte[] value) {
            super("keyid", value);
        }

        public static KeyIdParam of(byte[] value) {
            if (value.length > 8) {
                throw new IllegalArgumentException("Key must be at most 8 bytes long");
            }
            return new KeyIdParam(value);
        }
    }

    public static final class DataParam extends Param<byte[]> {
        private DataParam(byte[] value) {
            super("data", value);
        }

        public static DataParam of(byte[] value) {
            if (value.length > 32) {
                throw new IllegalArgumentException("Key must be at most 32 bytes long");
            }
            return new DataParam(value);
        }
    }
}
