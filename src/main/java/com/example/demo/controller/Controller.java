package com.example.demo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.validation.Valid;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/")
public class Controller {
    @PostMapping("/encrypt")
    public ResponseEntity<Response> encryptTextAction(@Valid @RequestBody BodyApi body) {
        Response response;
        String seed =  body.getSeed();
        String texto =  body.getTexto();
        String result = "";

        try {
            byte[] key = seed.getBytes(StandardCharsets.UTF_8);
            key = Arrays.copyOf(key, 16);
            SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = cipher.doFinal(texto.getBytes());
            byte[] tmpByte = Base64.encodeBase64(encrypted);

            result = new String(tmpByte);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            result = texto;
        }

        response = new Response(HttpStatus.OK.value(), "El texto encriptado es: ", result);
        return new ResponseEntity<Response>(response, HttpStatus.OK);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<Response> decryptTextAction(@Valid @RequestBody BodyApi body) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Response response;
        String seed =  body.getSeed();
        String texto =  body.getTexto();
        String result = "";

        byte[] key = seed.getBytes(StandardCharsets.UTF_8);
        key = Arrays.copyOf(key, 16);
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        byte[] tmpBClave = Base64.decodeBase64(texto);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(tmpBClave);

        result = new String(decrypted);

        response = new Response(HttpStatus.OK.value(), "El texto sin encriptar es:", result);
        return new ResponseEntity<Response>(response, HttpStatus.OK);
    }
}
