import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.*;
import java.io.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.apache.commons.codec.binary.Base64;


public class CryptoHelper{
    
    private static Cipher rsaCipher = null;
    private static Cipher aesCipher = null;
    

    public CryptoHelper(){
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        //try to get instance as little as possible
        if(rsaCipher == null || aesCipher == null){
            try{
                //TODO: figure out why these lines are so damn slow
                rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                aesCipher = Cipher.getInstance("AES", "BC");
            }catch(Exception ex){
                System.out.println("RSA constructor error: " + ex);
            }
        }
    }

    //RSA Methods

    //Encrypt with string input and given key
    public byte[] encryptRSA(String input, Key key){
        byte[] out = null;
        try{
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            out = rsaCipher.doFinal(input.getBytes());
        }catch(Exception ex){
            System.out.println("enc rsa str:" + ex);
        }
        return out;
    }

    //Encrypt with byte array input and given key
    public byte[] encryptRSA(byte[] input, Key key){
        // System.out.println("enc Key: " + key.toString());
        byte[] out = null;
        try{
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            out = rsaCipher.doFinal(input);
        }catch(Exception ex){
            System.out.println("enc rsa byte:" + ex);
        }
        return out;
    }

    //Decrypt to byte array from byte array ciphertext and given key
    public byte[] decryptRSA(byte[] ciphertext, Key key){
        byte[] out = null;
        try{
            rsaCipher.init(Cipher.DECRYPT_MODE, key);
            out = rsaCipher.doFinal(ciphertext);
        }catch(Exception ex){
            System.out.println("dec rsa:" + ex);
        }
        return out;
    }

    //Hash token with sha256, then compare with RSA decrypted tokenHash
    public boolean checkToken(UserToken token, byte[] tokenHash, Key key){
        byte[] currTokenHash = sha256Bytes(token.toUniqueString());
        //decrypt string hash with server's public key
        byte[] decStringHash = decryptRSA(tokenHash, key);
        return Arrays.equals(currTokenHash, decStringHash);
    }

    //Generate new RSA keypair
    public KeyPair getNewKeypair(){
        KeyPairGenerator gen = null;
        try{
            gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(2048); //set key length to 2048
        }catch(Exception ex){
            System.out.println("Error in generating new keypair: " + ex);
        }
        return gen.generateKeyPair();
    }

    //AES methods

    public byte[] encryptAES(String input, Key key){
        byte[] out = null;
        try{
            aesCipher.init(Cipher.ENCRYPT_MODE, key);
            out = aesCipher.doFinal(input.getBytes());
        }
        catch(Exception e){
            System.out.println("Error encrypting aes: " + e);
        }
        return out;
    }

    public byte[] encryptAES(byte[] input, Key key){
        byte[] out = null;
        try{
            aesCipher.init(Cipher.ENCRYPT_MODE, key);
            out = aesCipher.doFinal(input);
        }
        catch(Exception e){
            System.out.println("Error encrypting aes: " + e);
        }
        return out;
    }

    public String decryptAES(byte[] ciphertext, Key key){
        String out = null;
        try{
            aesCipher.init(Cipher.DECRYPT_MODE, key);
            out = new String(aesCipher.doFinal(ciphertext));
        }
        catch(Exception e){
            System.out.println("Error decrypting aes: " + e);
        }
        return out;
    }

    public byte[] decryptAESBytes(byte[] ciphertext, Key key){
        byte[] out = null;
        try{
            aesCipher.init(Cipher.DECRYPT_MODE, key);
            out = aesCipher.doFinal(ciphertext);
        }
        catch(Exception e){
            System.out.println("Error decrypting aes: " + e);
        }
        return out;
    }

    public UserToken extractToken(Envelope e, int index, Key key){
		String token = this.decryptAES(((byte [])e.getObjContents().get(index)), key);
		String [] spl = token.split(":|\\\n");
		String [] grpss = spl[5].split(",|\\[|\\]|\\ ");
		ArrayList<String> trial = new ArrayList<String>();
		for(int i = 0; i < grpss.length; i++){
			if((i % 2) != 0)
				trial.add(trial.size(), grpss[i]);
		}
		UserToken yourToken = (UserToken)new Token(spl[1], spl[3], trial);
		return yourToken;
    }

    public List<String> extractList(Envelope e, int index, Key key){
		String token = this.decryptAES(((byte [])e.getObjContents().get(index)), key);
		String [] spl = token.split(",|\\[|\\]|\\ ");
		//String [] grpss = spl[5].split(",|\\[|\\]|\\ ");
		List<String> trial = new ArrayList<String>();
		for(int i = 0; i < spl.length; i++){
			if((i % 2) != 0)
				trial.add(trial.size(), spl[i]);
		}
		return trial;
	}

    public String sha256(String s){
        SHA256Digest sha = new SHA256Digest();
        sha.update(s.getBytes(), 0, s.getBytes().length);
        byte[] out = new byte[32];
        sha.doFinal(out, 0);
        return Base64.encodeBase64String(out);
    }

    public byte[] sha256Bytes(String s){
        SHA256Digest sha = new SHA256Digest();
        sha.update(s.getBytes(), 0, s.getBytes().length);
        byte[] out = new byte[32];
        sha.doFinal(out, 0);
        return out;
    }
    public byte[] sha256Bytes(byte [] s){
        SHA256Digest sha = new SHA256Digest();
        sha.update(s, 0, s.length);
        byte[] out = new byte[64];
        sha.doFinal(out, 0);
        return out;
    }
    private byte[] serialize(Object obj) throws IOException {
        try(ByteArrayOutputStream b = new ByteArrayOutputStream()){
            try(ObjectOutputStream o = new ObjectOutputStream(b)){
                o.writeObject(obj);
            }
            catch(Exception e){
                
            }
            return b.toByteArray();
        }
        catch(Exception e){
            
        }
        return null;
    }

    
    public byte [] HMAC(byte [] key, Envelope message){
        byte [] ret = null;
        byte [] mes = null;
        try{
            mes = serialize((Object) message);
        }catch(Exception e){

        }

        //System.out.println(key.length);
        if(key.length > 64){
            key = sha256Bytes(key);
        }
        if(key.length < 64){
            while(key.length < 64)
                key = padArray(key);
        }
        //System.out.println(key.length);
        //System.out.println(key.toString());
        //System.out.println(Arrays.toString(mes));
        ByteBuffer wrap = ByteBuffer.wrap(key);
        int k = wrap.getInt();
        byte [] opad = getOpad(k);
        byte [] ipad = getIpad(k);
        try{
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(ipad);
            out.write(mes);
            byte [] c = out.toByteArray();
            byte [] firstPart = sha256Bytes(opad);
            byte [] secondPart = sha256Bytes(c);
            out.reset();
            out.write(firstPart);
            out.write(secondPart);
            return out.toByteArray();
        }
        catch(Exception e){

        }
        return null;
    }
    private byte [] getOpad(int key){
        int ret = key ^(0x5c * 64);
        ByteBuffer wrap = ByteBuffer.allocate(32);
        wrap.putInt(ret);
        return wrap.array();

    }
    private byte [] getIpad(int key){
        int ret = key ^(0x36 * 64);
        ByteBuffer wrap = ByteBuffer.allocate(32);
        wrap.putInt(ret);
        return wrap.array();
    }
    private byte [] padArray(byte [] arr){
        byte [] ret = new byte [64];
        for(int i = 0; i < arr.length; i++){
            ret[i] = arr[i];
        }
        for(int i = ret.length-arr.length; i < ret.length; i++){
            ret[i] = 0;
        }
        //System.out.println(Arrays.toString(ret));
        return ret;
   }
}