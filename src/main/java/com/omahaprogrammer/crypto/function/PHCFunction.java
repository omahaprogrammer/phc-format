/*
 * Copyright 2019 Jonathan Paz <omahaprogrammer@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.omahaprogrammer.crypto.function;

import java.util.*;

public abstract class PHCFunction<T extends PHCFunction<T>> {
    private final String id;

    PHCFunction(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public abstract <V> Optional<Param<T,V>> getParam(String string);

    public abstract byte[] hashPassword(Map<Param<T, ?>, ?> params, byte[] salt, char[] password, int length);

    public abstract int getDefaultSaltLength();

    public abstract int getDefaultHashLength();

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

        int getPriority() {
            return priority;
        }

        public Class<V> getValueClass() {
            return valueClass;
        }

        V getValue(Map<? extends Param<?, ?>, ?> map) {
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
