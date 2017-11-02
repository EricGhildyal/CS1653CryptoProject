import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;	
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import java.util.Random;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.agreement.DHAgreement;


//import javax.crypto.interfaces.DHPublicKey;
//import javax.crypto.spec.DHParameterSpec;

import java.io.NotSerializableException;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	public UserToken tok;
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;


	/**
	 * Connects to server from param server on port param port
	 *
	 * @param server server hostname/issuer of token
	 * @param port port that server is connected to
	 * @return Whether or not the connection was sucessful or not
	 */
	public boolean connect(final String server, final int port){
		try {	
			this.sock = new Socket(server, port);
			//System.out.println(server);	
			output = new ObjectOutputStream(this.sock.getOutputStream());  //Declare the output and input streams
			input = new ObjectInputStream(this.sock.getInputStream());
			Provider bcp = new BouncyCastleProvider();
			DHParametersGenerator paramGen = new DHParametersGenerator();
			SecureRandom secRand = new SecureRandom();
			paramGen.init(256, 90, secRand);
			DHParameters params = paramGen.generateParameters();
			//System.out.println(params.getG().toString());
			BigInteger g = params.getG();
			BigInteger p = params.getP();
			
			DHKeyGenerationParameters keyGenParams = new DHKeyGenerationParameters(secRand, params);
			DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
			keyGen.init(keyGenParams);
			//need to send keyGen to client here.
			//Envelope env = (Envelope) (Object)keyGen;
			AsymmetricCipherKeyPair clientKeys = keyGen.generateKeyPair();
			DHPublicKeyParameters publicKeyParam = (DHPublicKeyParameters)clientKeys.getPublic();
			DHPrivateKeyParameters privateKeyParam = (DHPrivateKeyParameters)clientKeys.getPrivate();
			BigInteger pubKey = publicKeyParam.getY();
			Envelope gMSG = new Envelope("g");
			gMSG.addObject(g);
			output.writeObject(gMSG);
			//output.reset();
			Envelope pMSG = new Envelope("p");
			pMSG.addObject(p);
			output.writeObject(pMSG);
			//output.reset();
			Envelope pubMSG = new Envelope("pubKey");
			pubMSG.addObject(pubKey);
			output.writeObject(pubMSG);
			output.flush();
			System.out.println(pubKey);


			Envelope servPubKey = (Envelope)input.readObject();
			ArrayList<Object> pub = servPubKey.getObjContents();
			BigInteger serverPub = (BigInteger)pub.get(0);
			//System.out.println(serverPub);
			DHPublicKeyParameters servPub = new DHPublicKeyParameters(serverPub, params);
			DHAgreement keyAgree = new DHAgreement();
			keyAgree.init(clientKeys.getPrivate());
			BigInteger msg = keyAgree.calculateMessage();
			BigInteger key = keyAgree.calculateAgreement(servPub,BigInteger.TEN);
			
		}catch(Exception e){
			System.out.println("There was an error in connecting to the server: " + e);
			return false;
		}
		return true;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
