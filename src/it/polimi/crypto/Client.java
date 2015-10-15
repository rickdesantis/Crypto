package it.polimi.crypto;

import it.polimi.crypto.elements.Message;
import it.polimi.crypto.elements.Message.Parameter;
import it.polimi.crypto.elements.MessageName;
import it.polimi.crypto.elements.ParameterName;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Client {
	
	private static final Logger logger = LoggerFactory.getLogger(Client.class);
	
	private byte[] serverRandomNumber;
	
	private String publicKey;
	private RSAPublicKey actualPublicKey;
	private byte[] masterSecret;
	
	private boolean encryptedMode = false;
	private boolean handshaken = false;
	
	private Server server;
	
	private List<Message> handshakeMessages;
	
	public static final String FINISHED_LABEL = "client finished";
	
	public static final byte[] RANDOM_NUMBER = {
		31, 32,
		21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		 1,  2,  3,  4,  5,  6,  7,  8,  9, 10
		};
	
	public static final byte[] PRE_MASTER_SECRET = {
		 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
		31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48
		};
	
	public void handshake() throws CryptoException {
		if (server == null)
			throw new CryptoException("The client isn't connected to any server.");

		// The handshake protocol is described in RFC 5246
		// http://tools.ietf.org/html/rfc5246#section-7.4
		
		handshakeMessages = new ArrayList<Message>();
		
		sendMessage(new Message(
				MessageName.ClientHello, 
				new Parameter(ParameterName.randomNumber, RANDOM_NUMBER)));
	}

	public void connect(Server server) throws CryptoException {
		if (this.server != null)
			throw new CryptoException("The client is already connected to another server.");
		else if (server == null)
			throw new CryptoException("Trying to connect to a non valid server.");
		server.addClient(this);
		this.server = server;
	}
	
	public void disconnect() throws CryptoException {
		if (server == null)
			throw new CryptoException("The client wasn't connected to any server.");
		server.removeClient(this);
		server = null;
		encryptedMode = false;
		handshaken = false;
	}
	
	public void sendMessage(Message m) throws CryptoException {
		if (server == null)
			throw new CryptoException("The client isn't connected to any server.");
		logger.trace("Client> {}", m.getBody());
		
		if (!handshaken && m.getMessageName() != null && m.getMessageName() != MessageName.Finished)
			handshakeMessages.add(m);
		
		server.receiveMessage(this, m);
	}
	
	public void sendSecureMessage(Message m) throws CryptoException {
		if (server == null)
			throw new CryptoException("The client isn't connected to any server.");
		else if (!encryptedMode)
			throw new CryptoException("The handshake phase wasn't completed.");
		logger.trace("Client (Secure)> {}", m.getBody());
		
		String body = Crypter.byteArrayToString(Crypter.encryptWithPassword(Crypter.stringToByteArray(m.getBody()), masterSecret));
		
		Message newm = new Message(body, m.getParams());
		
		if (!handshaken && m.getMessageName() != null && m.getMessageName() != MessageName.Finished)
			handshakeMessages.add(newm);
		
		server.receiveSecureMessage(this, newm);
	}
	
	public void receiveMessage(Server server, Message m) throws CryptoException {
		if (this.server == null)
			throw new CryptoException("The client isn't connected to any server.");
		else if (server == null)
			throw new CryptoException("The server provided isn't valid.");
		else if (this.server != server)
			throw new CryptoException("The client is connected to another server.");
		
		if (!handshaken && m.getMessageName() != null && m.getMessageName() != MessageName.Finished)
			handshakeMessages.add(m);
		
		parseMessage(server, m);
	}
	
	public void receiveSecureMessage(Server server, Message m) throws CryptoException {
		if (this.server == null)
			throw new CryptoException("The client isn't connected to any server.");
		else if (server == null)
			throw new CryptoException("The server provided isn't valid.");
		else if (this.server != server)
			throw new CryptoException("The client is connected to another server.");
		else if (!encryptedMode)
			throw new CryptoException("The handshake phase wasn't completed.");
		
		String body = Crypter.byteArrayToString(Crypter.decryptWithPassword(Crypter.stringToByteArray(m.getBody()), masterSecret));
		
		Message newm = new Message(body, m.getParams());
		
		if (!handshaken && newm.getMessageName() != null && newm.getMessageName() != MessageName.Finished)
			handshakeMessages.add(m);
		
		parseSecureMessage(server, newm);
	}
	
	private void parseMessage(Server server, Message m) throws CryptoException {
		switch (m.getMessageName()) {
		case ServerHello:
			serverRandomNumber = (byte[]) m.getParam(ParameterName.randomNumber);
			break;
		case Certificate:
			publicKey = (String) m.getParam(ParameterName.publicKey);
			actualPublicKey = Crypter.getPublicKey(publicKey);
			break;
		case ServerHelloDone:
			byte[] cryptedPreMasterSecret = Crypter.encryptWithKey(PRE_MASTER_SECRET, actualPublicKey, Crypter.PUBLIC_KEY_ALGORITHM);
			
			sendMessage(new Message(
					MessageName.ClientKeyExchange,
					new Parameter(ParameterName.preMasterSecret, cryptedPreMasterSecret)));
			
			sendMessage(new Message(
					MessageName.ChangeCipherSpec));
			break;
		case ChangeCipherSpec:
			encryptedMode = true;
			
			masterSecret = Crypter.getMasterSecret(PRE_MASTER_SECRET, RANDOM_NUMBER, serverRandomNumber);
			
			byte[] verifyData = Crypter.pseudoRandomFunction(masterSecret, FINISHED_LABEL, Crypter.stringToByteArray(Message.getHash(handshakeMessages)));
			
			sendMessage(new Message(
					MessageName.Finished,
					new Parameter(ParameterName.verifyData, verifyData)));
			break;
		case Finished:
			byte[] receivedVerifyData = (byte[]) m.getParam(ParameterName.verifyData);
			byte[] serverVerifyData = Crypter.pseudoRandomFunction(masterSecret, Server.FINISHED_LABEL, Crypter.stringToByteArray(Message.getHash(handshakeMessages)));
			
			if (!Arrays.equals(receivedVerifyData, serverVerifyData))
				throw new CryptoException("The stream cannot be encrypted.");
			
			handshaken = true;
			break;
		default:
			break;
		}
	}
	
	private void parseSecureMessage(Server server, Message m) throws CryptoException {
		if (!handshaken)
			throw new CryptoException("The session wasn't authenticated.");
	}

}
