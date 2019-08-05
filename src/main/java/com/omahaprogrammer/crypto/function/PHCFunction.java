package com.omahaprogrammer.crypto.function;

import java.util.*;

public abstract class PHCFunction<T extends PHCFunction<T>> {
    private static final Map<String, PHCFunction<?>> functions = new HashMap<>();

    public static final Argon2i ARGON2_I;
    public static final Argon2d ARGON2_D;
    public static final Argon2id ARGON2_ID;
    public static final PBKDF2 PBKDF2;

    public static Optional<PHCFunction<?>> getFunction(String string) {
        return Optional.ofNullable(functions.get(string));
    }

    private final String id;

    static {
        ARGON2_I = new Argon2i();
        ARGON2_D = new Argon2d();
        ARGON2_ID = new Argon2id();
        PBKDF2 = new PBKDF2();
    }

    PHCFunction(String id) {
        this.id = id;
        functions.put(id, this);
    }

    public String getId() {
        return id;
    }

    public abstract Optional<Param<?,?>> getParam(String string);

    public abstract byte[] hashPassword(Map<Param<?, ?>, ?> params, byte[] salt, char[] password);

    public abstract static class Param<T extends PHCFunction<T>, V> implements Comparable<Param<T, V>> {

        private final String name;
        private final int priority;
        private final Class<V> valueClass;

        Param(String name, int priority, Class<V> valueClass) {
            this.name = name;
            this.priority = priority;
            this.valueClass = Objects.requireNonNull(valueClass);
        }

        public String getName() {
            return name;
        }

        public int getPriority() {
            return priority;
        }

        public Class<V> getValueClass() {
            return valueClass;
        }

        public V getValue(Map<? extends Param<?, ?>, ?> map) {
            return validate(map.get(this));
        }

        public V validate(Object obj) {
            if (obj == null) {
                return null;
            }
            if (obj instanceof String) {
                obj = convertString(obj.toString(), valueClass);
            }

            if (!valueClass.isInstance(obj)) {
                throw new IllegalArgumentException();
            }
            V val = valueClass.cast(obj);
            validateImpl(valueClass.cast(obj));
            return val;
        }

        protected abstract void validateImpl(V value);

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Param<?, ?> param = (Param<?, ?>) o;
            return Objects.equals(name, param.name) &&
                    priority == param.priority &&
                    valueClass.equals(param.valueClass);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, priority, valueClass);
        }

        @Override
        public String toString() {
            return getName();
        }

        @Override
        public int compareTo(Param<T, V> o) {
            return Comparator.<Param<T, V>>comparingInt(Param::getPriority)
                    .thenComparing(Param::getName, Comparator.nullsFirst(Comparator.naturalOrder()))
                    .thenComparing(p -> p.getValueClass().getName())
                    .compare(this, o);
        }

        private static <V> V convertString(String val, Class<V> clazz) {
            if (clazz.equals(String.class)) {
                return clazz.cast(val);
            }
            if (clazz.equals(Integer.class)) {
                return clazz.cast(Integer.valueOf(val));
            }
            if (clazz.equals(byte[].class)) {
                return clazz.cast(Base64.getDecoder().decode(val));
            }
            throw new IllegalArgumentException("Unknown conversion");
        }
    }
}
