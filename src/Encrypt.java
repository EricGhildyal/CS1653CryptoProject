import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
public class Encrypt{
    SecretKeySpec key;
    public Encrypt(SecretKeySpec key){
        this.key = key;
        //System.out.println(key.getEncoded());
        //System.out.println(key.getFormat());
    }

    public byte[] encryptAES(String toEncrypt){
        byte [] ret = null;
        try{
            
            Cipher encCipher = Cipher.getInstance("AES");
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            ret = encCipher.doFinal(toEncrypt.getBytes());
        }
        catch(Exception e){
            System.out.println(e);
        }
        return ret;
    }

    public String decryptAES(byte [] toDecrypt){
        String ret = null;
        try{
            Cipher decCipher = Cipher.getInstance("AES");
            decCipher.init(Cipher.DECRYPT_MODE, key);
            
            ret = new String(decCipher.doFinal(toDecrypt));
        }
        catch(Exception e){

        }

        return ret;
    }
}