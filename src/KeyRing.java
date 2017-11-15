import java.util.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import org.bouncycastle.jce.*;
import org.bouncycastle.x509.*;
import java.math.*;
import org.apache.commons.codec.binary.Base64;

//Wrapper class for KeyStore to fit our needs
public class KeyRing{
   
    private String alias;
    private HashMap<String, byte[]> ring;

    public KeyRing(String name){
        this.alias = name;
        ring = new HashMap<String, byte[]>();
    }

    public void addKey(String alias, Key key){
        byte[] bytesEncoded = Base64.encodeBase64(key.getEncoded());
        ring.put(alias, bytesEncoded);
    }

    public Key getKey(String alias){
        byte[] base64Enc = ring.get(alias);
        byte[] decoded = Base64.decodeBase64(base64Enc);
        
        return null;
    }

    public void saveRing(){
        // check if folder named keys exists or not, create if it doesn't
        File keysFolder = new File(alias+"_keys");
        if(!keysFolder.isDirectory()){
            keysFolder.mkdir();
        }
        for(Map.Entry<String, byte[]> entry : ring.entrySet()){
            String alias = entry.getKey();
            byte[] k = entry.getValue();
        }
        
    }

    public void loadRing(){
        // check if folder named keys exists or not, create if it doesn't
        File keysFolder = new File(alias+"_keys");
        if(!keysFolder.isDirectory()){
            return;
        }

    }

    // private Key readPemFile(File keyFile){
    //     PEMParser parser;
    //     try{
    //         // parser = new PEMParser(new FileReader(keyFile));
    //         // Object obj = parser.readObject();
    //         PEMReader pem = new PEMReader(new FileReader(keyFile));
    //         RSACryptoServiceProvider rsa = pem.ReadPrivateKeyFromFile(keyFile);            
    //         // System.out.println(obj.getClass());
    //     }catch(Exception ex){
    //         System.out.println("Error reading PEM file: " + ex);
    //     }
    //     return null;
    // }

    // //writes key to PEM file with name fileName
    // private void writePemFile(Key key, File keyFile){
    //     FileOutputStream fileOutStream = null;
    //     JcaPEMWriter writer = null;
    //     System.out.println(key.getClass());
    //     try{
    //         fileOutStream = new FileOutputStream(keyFile); 
    //         writer = new JcaPEMWriter(new OutputStreamWriter(fileOutStream));
    //         writer.writeObject(key);
    //         writer.close();
    //     }catch(Exception ex){
    //         System.out.println("Error wrtiting PEM file: " + ex);
    //     }
    // }

}