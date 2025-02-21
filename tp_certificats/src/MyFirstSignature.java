import util.ByteToHex;

import java.security.*;
import javax.crypto.Cipher;
import java.util.Arrays;

public class MyFirstSignature {

    protected String myMessage;
    protected PrivateKey privateKey;
    protected PublicKey publicKey;

    public MyFirstSignature(String myMessage){
        this.myMessage = myMessage;
        this.generateKeyPair();
    }

    /**
     * Generates the key pair and assignates both keys
     * to the class variables
     */
    private void generateKeyPair(){
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.generateKeyPair();
            this.privateKey = kp.getPrivate();
            this.publicKey = kp.getPublic();

        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Encrypts a message through the private key in RSA mode
     * @param pTabSig
     * @return
     */
    private byte[] encrypt (byte[] pTabSig){
        Cipher c = null;
        try {
            c = Cipher.getInstance("RSA");
            c.init(Cipher.ENCRYPT_MODE, this.privateKey);
            return c.doFinal(pTabSig);
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public byte[] sign(){
        try {
            // hash the message
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(this.myMessage.getBytes());
            return this.encrypt(h);
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }


    private byte[] decrypt (byte[] pCondensat){
        Cipher c = null;
        try {
            c = Cipher.getInstance("RSA");
            c.init(Cipher.DECRYPT_MODE, this.publicKey);
            byte[] decrypted = c.doFinal(pCondensat);
            return decrypted;

        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public boolean verifySignature(byte pCondensat[]){
        boolean ret = false;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(this.myMessage.getBytes());
            byte[] decrypted = this.decrypt(pCondensat);
            if (Arrays.compare(h, decrypted) == 0){
                ret = true;
            } else {
                ret = false;
            }

        } catch (Exception e){
            e.printStackTrace();
        }
        return ret;
    }

}
