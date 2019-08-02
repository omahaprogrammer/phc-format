package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2i extends Argon2<Argon2i> {
    public Argon2i INSTANCE = new Argon2i();

    private Argon2i() {
        super("argon2i", Argon2Parameters.ARGON2_i);
    }
}
