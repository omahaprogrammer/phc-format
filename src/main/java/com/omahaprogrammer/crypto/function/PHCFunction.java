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

/**
 * The root class for all functions that protect passwords stored in a PHC.
 * @param <T> The class of the function
 */
public abstract class PHCFunction<T extends PHCFunction<T>> {
    /**
     * The identifier for this function
     */
    private final String id;

    /**
     * Creates a new function object
     * @param id the function identifier
     */
    PHCFunction(String id) {
        this.id = id;
    }

    /**
     * Retrieves this function's identifier
     * @return the function identifier
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the parameter associated with the given parameter id. This method is intended to support the PHC parsing system.
     * @param paramId the parameter identifier.
     * @param <V> The type the parameter supports for its related value
     * @return the parameter object
     */
    public abstract <V> Optional<Param<T,V>> getParam(String paramId);

    /**
     * Protects the given password by applying the function described by this object with the given params and salt,
     * producing an array of {@code length} bytes. This method is intended to be executed by the PHC only.
     * @param params the parameters necessary for this function
     * @param salt the cryptographic salt
     * @param password the cleartext password
     * @param length the output length
     * @return the protected password
     */
    public abstract byte[] protectPassword(Map<Param<T, ?>, ?> params, byte[] salt, char[] password, int length);

    /**
     * Supplies the default length in bytes of a cryptographic salt for this function
     * @return the default length in bytes
     */
    public abstract int getDefaultSaltLength();

    /**
     * Supplies the default length in bytes of the protected password for this function
     * @return the default length in bytes
     */
    public abstract int getDefaultHashLength();

    /**
     * This class defines a parameter for a password protection function. Each function instance should make singleton
     * instances of extensions of this class for users to access. This class implements {@code Comparable} to allow for
     * instances to be sorted according to priority order for presentation in a string representation of a PHC.
     * @param <T> the type of the function
     * @param <V> the type of the value associated with this parameter
     */
    public abstract static class Param<T extends PHCFunction<T>, V> implements Comparable<Param<T, V>> {
        /**
         * The plain name of the parameter
         */
        private final String name;

        /**
         * The priority where this parameter will show up in the list of parameters in the PHC
         */
        private final int priority;

        /**
         * The class describing the type accepted for the value
         */
        private final Class<V> valueClass;

        /**
         * Creates the new parameter. This constructor should never be made available publicly.
         * @param name the plan name of the parameter
         * @param priority the priority for the parameter
         * @param valueClass the class of the value
         */
        Param(String name, int priority, Class<V> valueClass) {
            this.name = name;
            this.priority = priority;
            this.valueClass = Objects.requireNonNull(valueClass);
        }

        /**
         * Retrieves the plain name of the parameter as displayed in the PHC string
         * @return the name of the parameter
         */
        public String getName() {
            return name;
        }

        /**
         * Retrieves the priority of the parameter as displayed in the list of parameters in the PHC string
         * @return the parameter priority
         */
        int getPriority() {
            return priority;
        }

        /**
         * The class representing the acceptable value for the parameter
         * @return the value class
         */
        public Class<V> getValueClass() {
            return valueClass;
        }

        /**
         * Retrieves the value of the parameter from the given map. This provides for typing safety.
         * @param map the map of parameter-value pairs
         * @return the value associated with this parameter
         */
        V getValue(Map<? extends Param<?, ?>, ?> map) {
            return validate(map.get(this));
        }

        /**
         * Validates the given object to confirm that it is assignable to this parameter
         * @param obj the desired value to set to the parameter
         * @return the actual value, possibly transformed to the proper type
         * @throws IllegalArgumentException If the value is invalid for this parameter type
         */
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

        /**
         * Additional value checking to be implemented by a subclass
         * @param value the value to be checked
         */
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

        /**
         * This method converts a string value into an Integer or Enum as necessary
         * @param val the value to convert to the specified class
         * @param clazz the value class to convert the string into
         * @param <V> the type of the value
         * @return the converted value
         */
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
