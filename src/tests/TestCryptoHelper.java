import static org.junit.Assert.*;

import java.io.File;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.KeyGenerator;

import org.bouncycastle.util.encoders.Base64;
import org.junit.*;

public class TestCryptoHelper{
    public static CryptoHelper crypto = new CryptoHelper();
    public static Key k;
    public static KeyPair kp;
    public static KeyRing keyRing;
    
    @BeforeClass
    public static void setUp() {
        System.out.println("Setting up keys");
        k = getAESKey();
        kp = getRSAKeypair();
        keyRing = new KeyRing("tester");
        keyRing.init();
        keyRing.addKey("aes", k);
        keyRing.addKey("rsa_pub", kp.getPublic());
        keyRing.addKey("rsa_priv", kp.getPrivate());
    }
    
    private static Key getAESKey() {
    	KeyGenerator gen = null;
        try{
          gen = KeyGenerator.getInstance("AES", "BC");
          gen.init(256);
        }catch(Exception ex){
          System.out.println(ex);
        }
        return gen.generateKey();
    }
    
    private static KeyPair getRSAKeypair() {
    	KeyPairGenerator gen = null;
        try{
            gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(2048); //set key length to 2048
        }catch(Exception ex){
            System.out.println("Error in generating new keypair: " + ex);
        }
        return gen.generateKeyPair();
    }
    
    @Test
    public void testGetNewKeyPair(){
    	KeyPair testKP = crypto.getNewKeypair();
    	assertTrue(testKP.getPrivate() != null);
    	assertTrue(testKP.getPublic() != null);
    }
    
    @Test
    public void testKeyRingFile() {
    	crypto.saveRing(keyRing);
    	File file = new File(keyRing.getAlias() +"_keys" + File.separator + "keys.bin");
    	assertTrue(file.exists());
    }
    
    @Test
    public void testKeyRingInvalid() {
    	assertTrue(keyRing.getKey("test") == null);
    	assertFalse(keyRing.getKey("rsa_pub").equals(keyRing.getKey("rsa_priv")));
    }
   
    @Test
    public void testKeyRingSaveLoad() {
    	crypto.saveRing(keyRing);
    	KeyRing newKR = new KeyRing("tester");
    	newKR = crypto.loadRing(newKR);
    	assertEquals(keyRing.getKey("aes"), newKR.getKey("aes"));
    	assertEquals(keyRing.getKey("rsa_pub"), newKR.getKey("rsa_pub"));
    	assertEquals(keyRing.getKey("rsa_priv"), newKR.getKey("rsa_priv"));    	
    }
    
    @Test
    public void testRSAEncDecPrivToPub() {
    	String inStr = "this is another input string";
    	byte[] ciphertext = crypto.encryptRSA(inStr, kp.getPrivate());
    	String outStr = new String(crypto.decryptRSA(ciphertext, kp.getPublic()));
    	
    	assertEquals(inStr, outStr);
    }
    
    @Test(expected=java.lang.NullPointerException.class)
    public void testRSAEncDecPrivToPubInvalid() {
    	String inStr = "this is another input string";
    	byte[] ciphertext = crypto.encryptRSA(inStr, kp.getPrivate());
        //change part of ciphertext
        ciphertext[1] = (byte) (ciphertext[1] >> 2);
        String outStr = new String(crypto.decryptRSA(ciphertext, kp.getPublic()));
        
        assertNotEquals(inStr, outStr);
    }
    
    @Test
    public void testRSAEncDecPubToPriv() {
    	String inStr = "this is another input string";
    	byte[] ciphertext = crypto.encryptRSA(inStr, kp.getPublic());
    	String outStr = new String(crypto.decryptRSA(ciphertext, kp.getPrivate()));
    	
    	assertEquals(inStr, outStr);
    }

    @Test(expected=java.lang.NullPointerException.class)
    public void testRSAEncDecPubToPrivInvalid() {
    	String inStr = "this is another input string";
    	byte[] ciphertext = crypto.encryptRSA(inStr, kp.getPublic());
    	//change part of ciphertext
    	ciphertext[1] = (byte) (ciphertext[1] >> 2);
    	String outStr = new String(crypto.decryptRSA(ciphertext, kp.getPrivate()));
    	
    	assertNotEquals(inStr, outStr);
    }
    
    @Test
    public void testAESEncDec(){
    	String inStr = "this is an input string";
    	byte[] ciphertext = crypto.encryptAES(inStr.getBytes(), k);
    	String outStr = crypto.decryptAES(ciphertext, k);
    	
    	assertEquals(inStr, outStr); 
    }
    
    @Test
    public void testAESEncDecInvalid(){
    	String inStr = "this is an input string";
    	byte[] ciphertext = crypto.encryptAES(inStr.getBytes(), k);
    	//change part of ciphertext
    	ciphertext[1] = (byte) (ciphertext[1] >> 2);
    	String outStr = crypto.decryptAES(ciphertext, k);
    	
    	assertNotEquals(inStr, outStr); 
    }
    
    @Test
    public void testSHA256() {
    	//Hash of "this is a test message"
    	String b64Hash = "Tkqgm22A771oToD1SnDB2GBWJcM4D0ywErMmRKACtb4=";
    	byte[] out = Base64.encode(crypto.sha256Bytes("this is a test message"));
    	assertEquals(b64Hash, new String(out));
    }
    
    @Test
    public void testCheckTarget() {
    	byte[] keyBytes = kp.getPublic().getEncoded();
    	String target = Base64.toBase64String(keyBytes);
    	assertTrue(crypto.checkTarget(target, kp.getPublic()));
    	
    }

}