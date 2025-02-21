import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

public class MySecondSignature extends MyFirstSignature {

    public MySecondSignature(String msg){
        super(msg);
    }

    @Override
    public byte[] sign(){
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(this.privateKey);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(this.myMessage.getBytes());
            s.update(h);
            return s.sign();
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verifySignature(byte[] pCondensat){
        boolean ret;
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(this.publicKey);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(this.myMessage.getBytes());
            s.update(h);
            return s.verify(pCondensat);

        } catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
}
