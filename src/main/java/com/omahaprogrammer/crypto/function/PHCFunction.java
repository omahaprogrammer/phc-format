package com.omahaprogrammer.crypto.function;

import java.util.Base64;
import java.util.Objects;
import java.util.Set;

public abstract class PHCFunction {
    private final String id;

    protected PHCFunction(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public abstract byte[] hashPassword(Set<Param<?>> params, char[] password);

    public static abstract class Param<T> {
        private final String name;
        private final T value;

        protected Param(String name, T value) {
            this.name = Objects.requireNonNull(name);
            this.value = Objects.requireNonNull(value);
        }

        public String getName() {
            return name;
        }

        public T getValue() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Param<?> param = (Param<?>) o;
            return name.equals(param.name) &&
                    value.equals(param.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, value);
        }

        @Override
        public String toString() {
            if (value instanceof byte[]) {
                return String.format("%s=%s", name, Base64.getEncoder().withoutPadding().encodeToString((byte[]) value));
            } else {
                return String.format("%s=%s", name, value);
            }
        }
    }
}
