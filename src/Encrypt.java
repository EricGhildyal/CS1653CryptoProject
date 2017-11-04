import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;
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

    public UserToken extractToken(Envelope e, Encrypt enc, int index){
		String token = enc.decryptAES(((byte [])e.getObjContents().get(index)));
		String [] spl = token.split(":|\\\n");
		String [] grpss = spl[5].split(",|\\[|\\]|\\ ");
		ArrayList<String> trial = new ArrayList<String>();
		for(int i =0; i<grpss.length; i++){
			if((i % 2) != 0)
				trial.add(trial.size(), grpss[i]);
		}
		UserToken yourToken = (UserToken)new Token(spl[1], spl[3], trial);
		return yourToken;

    }
    
    public List<String> extractList(Envelope e, Encrypt enc, int index){
		String token = enc.decryptAES(((byte [])e.getObjContents().get(index)));
		String [] spl = token.split(",|\\[|\\]|\\ ");
		//String [] grpss = spl[5].split(",|\\[|\\]|\\ ");
		List<String> trial = new ArrayList<String>();
		for(int i =0; i<spl.length; i++){
			if((i % 2) != 0)
				trial.add(trial.size(), spl[i]);
		}
		
		return trial;
	}
}