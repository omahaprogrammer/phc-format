package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2id extends Argon2<Argon2id> {
    public static final Argon2id INSTANCE = new Argon2id();

    private Argon2id() {
        super("argon2id", Argon2Parameters.ARGON2_id);
    }
}
