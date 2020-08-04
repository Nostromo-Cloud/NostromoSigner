package com.nostromo.main.signer;

import com.nostromo.api.signer.ISigner;
import javax.crypto.*;
import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Signer implements ISigner {

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
         KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
         generator.initialize(2048, new SecureRandom());
         return generator.generateKeyPair();
    }

    @Override
    public byte[] encrypt(byte[] bytes, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
         Cipher encrypt = Cipher.getInstance("RSA");
         encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
         return Base64.getEncoder().encode(encrypt.doFinal(bytes));
    }

    @Override
    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decrypt = Cipher.getInstance("RSA");
        decrypt.init(Cipher.DECRYPT_MODE, privateKey);
        return decrypt.doFinal(bytes);
    }

    @Override
    public byte[] sign(byte[] bytes, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(bytes);
        return Base64.getEncoder().encode(signature.sign());
    }

    @Override
    public boolean verify(byte[] bytes, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
         Signature verify = Signature.getInstance("SHA256withRSA");
         verify.initVerify(publicKey);
         verify.update(bytes);
         byte[] signatureBytes = Base64.getDecoder().decode(signature);
         return verify.verify(signatureBytes);
    }

    @Override
    public PublicKey get(String filename) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
