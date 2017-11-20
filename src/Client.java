import java.net.Socket;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.*;
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
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	public TokenTuple tokTuple;
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public BigInteger confidentialityKey;
	public BigInteger integrityKey;

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
			//Declare the output and input streams
			output = new ObjectOutputStream(this.sock.getOutputStream());
			input = new ObjectInputStream(this.sock.getInputStream());
			//run Diffie Hellman method to start connection
			setupDH();


		}catch(java.net.SocketException s){
			//do nothing
		}catch(Exception e){
			System.out.println("There was an error in connecting to the server: " + e);
			return false;
		}
		return true;
	}

	private void setupDH(){
		try{
			//generate parameters
			Provider bcp = new BouncyCastleProvider();
			DHParametersGenerator paramGen = new DHParametersGenerator();
			SecureRandom secRand = new SecureRandom();
			paramGen.init(255, 90, secRand);
			DHParameters params = paramGen.generateParameters();
			BigInteger g = params.getG();
			BigInteger p = params.getP();

			//generate keys and send p, g, and public key to server
			DHKeyGenerationParameters keyGenParams = new DHKeyGenerationParameters(secRand, params);
			DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
			keyGen.init(keyGenParams);
			AsymmetricCipherKeyPair clientKeys = keyGen.generateKeyPair();
			DHPublicKeyParameters publicKeyParam = (DHPublicKeyParameters)clientKeys.getPublic();
			DHPrivateKeyParameters privateKeyParam = (DHPrivateKeyParameters)clientKeys.getPrivate();
			BigInteger pubKey = publicKeyParam.getY();
			AsymmetricCipherKeyPair clientIntKeys = keyGen.generateKeyPair();
			DHPublicKeyParameters pubInt = (DHPublicKeyParameters)clientIntKeys.getPublic();
			BigInteger pubIntKey = pubInt.getY();
			Envelope dhMsgs = new Envelope("DHMSGS");
			dhMsgs.addObject(g);
			dhMsgs.addObject(p);
			dhMsgs.addObject(pubKey);
			dhMsgs.addObject(pubIntKey);
			output.writeObject(dhMsgs);

			//get server public key and agree on a session key
			Envelope servPubKey = (Envelope)input.readObject();
			ArrayList<Object> pub = servPubKey.getObjContents();
			BigInteger serverPub = (BigInteger)pub.get(0);
			BigInteger serverIntPub = (BigInteger)pub.get(1);
			DHPublicKeyParameters servPub = new DHPublicKeyParameters(serverPub, params);
			DHBasicAgreement keyAgree = new DHBasicAgreement();
			keyAgree.init(clientKeys.getPrivate());
			confidentialityKey = keyAgree.calculateAgreement(servPub);
			servPub = new DHPublicKeyParameters(serverIntPub, params);
			keyAgree = new DHBasicAgreement();
			keyAgree.init(clientIntKeys.getPrivate());
			integrityKey = keyAgree.calculateAgreement(servPub);

			output.reset();
		}catch(Exception e){
			System.out.println("Error during Diffie Hellman exchange: " + e);
		}
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
			}catch(java.net.SocketException s){
				//do nothing
			}catch(Exception e){
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
