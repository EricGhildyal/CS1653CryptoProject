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
public class KeyRing implements Serializable{
   
    private String alias;
    private HashMap<String, Key> ring;
    private static final long serialVersionUID = 42L;

    public KeyRing(String name){
        this.alias = name;
        ring = new HashMap<String, Key>();
    }

    //setup folder for saving/loading
    public void init(){
        File keysFolder = new File(alias+"_keys");
        keysFolder.mkdir();
    }

    // check if folder named keys exists or not, create if it doesn't
    public boolean exists(){
        File keysFolder = new File(alias+"_keys");
        if(!keysFolder.isDirectory()){
            
            return false;
        }
        return true;
    }

    public boolean addKey(String alias, Key key){
        if(alias == null || alias.equals("")){
            return false;
        }
        ring.put(alias, key);
        return true;
    }

    public Key getKey(String alias){
        if(alias == null || alias.equals("")){
            return null;
        }
        return ring.get(alias);
    }

    public String getAlias(){
        return alias;
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