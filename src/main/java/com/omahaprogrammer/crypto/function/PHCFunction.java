package com.omahaprogrammer.crypto.function;

import java.util.*;

public abstract class PHCFunction<T extends PHCFunction<T>> {
    private static final Map<String, PHCFunction<?>> functions = new HashMap<>();
    final Map<String, Param<T,?>> params = new HashMap<>();

    private final String id;

    PHCFunction(String id) {
        this.id = id;
        functions.put(id, this);
    }

    public String getId() {
        return id;
    }

    public static Optional<PHCFunction<?>> getFunction(String string) {
        return Optional.ofNullable(functions.get(string));
    }

    public Optional<Param<T,?>> getParam(String string) {
        return Optional.ofNullable(params.get(string));
    }

    public abstract byte[] hashPassword(Map<Param<?, ?>, ?> params, byte[] salt, char[] password);

    public abstract static class Param<T extends PHCFunction<T>, V> implements Comparable<Param<T, V>> {

        private final String name;
        private final int priority;
        private final T function;
        private final Class<V> valueClass;

        Param(String name, int priority, T function, Class<V> valueClass) {
            this.name = name;
            this.priority = priority;
            this.function = Objects.requireNonNull(function);
            this.valueClass = Objects.requireNonNull(valueClass);
            this.function.params.put(name, this);
        }

        public String getName() {
            return name;
        }

        public int getPriority() {
            return priority;
        }

        public T getFunction() {
            return function;
        }

        public Class<V> getValueClass() {
            return valueClass;
        }

        public V getFromMap(Map<? extends Param<?, ?>, ?> map) {
            return validate(map.get(this));
        }

        public V validate(Object obj) {
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
                    function.equals(param.function) &&
                    valueClass.equals(param.valueClass);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, priority, function, valueClass);
        }

        @Override
        public String toString() {
            return getName();
        }

        @Override
        public int compareTo(Param<T, V> o) {
            return Comparator.<Param<T, V>>comparingInt(Param::getPriority)
                    .thenComparing(Comparator.nullsFirst(Comparator.comparing(Param::getName)))
                    .thenComparing(p -> p.getFunction().getId())
                    .thenComparing(p -> p.getValueClass().getName())
                    .compare(this, o);
        }
    }
}
