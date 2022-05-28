package de.uni_passau.fim.pqsigningapp;

import org.junit.Test;

import static org.junit.Assert.*;

import com.example.liboqs.Signature;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void testSignature() {
        Signature cipher = new Signature("Falcon-512");
        byte[] message = "Hellow!".getBytes();
        byte[] publicKey = cipher.generate_keypair();
        byte[] signature = cipher.sign(message);
        assertTrue(cipher.verify(message, signature, publicKey));
    }
}