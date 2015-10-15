package it.polimi.crypto;

import it.polimi.crypto.elements.Message;
import it.polimi.crypto.elements.Message.Parameter;
import it.polimi.crypto.elements.MessageName;
import it.polimi.crypto.elements.ParameterName;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Server {
	
	private static final Logger logger = LoggerFactory.getLogger(Server.class);
	
	private List<Client> clients;
	
	private static String publicKey = null;
	
	private Map<Client, byte[]> clientsRandomNumbers;
	private Map<Client, byte[]> clientsPreMasterSecrets;
	private Map<Client, byte[]> clientsMasterSecrets;
	private Map<Client, Boolean> encryptedMode;
	private Map<Client, Boolean> handshaken;
	private Map<Client, List<Message>> handshakeMessages;
	
	public static final String FINISHED_LABEL = "server finished";
	
	public static final byte[] RANDOM_NUMBER = {
		 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
		31, 32
		};

	public Server() {
		clients = new ArrayList<Client>();
		clientsRandomNumbers = new HashMap<Client, byte[]>();
		clientsPreMasterSecrets = new HashMap<Client, byte[]>();
		clientsMasterSecrets = new HashMap<Client, byte[]>();
		encryptedMode = new HashMap<Client, Boolean>();
		handshaken = new HashMap<Client, Boolean>();
		handshakeMessages = new HashMap<Client, List<Message>>();
		if (publicKey == null)
			try {
				publicKey = Crypter.getKeyFromResource(Crypter.PUBLIC_KEY_PATH);
			} catch (CryptoException e) {
				logger.error("Error while reading the public key.", e);
				publicKey = null;
			}
	}
	
	public void addClient(Client c) throws CryptoException {
		if (clients.contains(c))
			throw new CryptoException("The client was already connected to the server!");
		clients.add(c);
		handshakeMessages.put(c, new ArrayList<Message>());
	}
	
	public void removeClient(Client c) throws CryptoException {
		if (!clients.contains(c))
			throw new CryptoException("The client wasn't connected to the server!");
		clients.remove(c);
		encryptedMode.remove(c);
		clientsPreMasterSecrets.remove(c);
		clientsMasterSecrets.remove(c);
		clientsRandomNumbers.remove(c);
		handshakeMessages.remove(c);
	}
	
	public void sendMessage(Client c, Message m) throws CryptoException {
		if (!clients.contains(c))
			throw new CryptoException("The client isn't connected to the server!");
		logger.trace("Server> {}", m.getBody());
		
		if ((!handshaken.containsKey(c) || !handshaken.get(c)) && m.getMessageName() != null && m.getMessageName() != MessageName.Finished)
			handshakeMessages.get(c).add(m);
		
		c.receiveMessage(this, m);
	}
	
	public void sendSecureMessage(Client c, Message m) throws CryptoException {
		if (!clients.contains(c))
			throw new CryptoException("The client isn't connected to the server!");
		else if (!encryptedMode.containsKey(c) || !encryptedMode.get(c))
			throw new CryptoException("The handshake phase wasn't completed.");
		logger.trace("Server (Secure)> {}", m.getBody());
		
		String body = Crypter.byteArrayToString(Crypter.encryptWithPassword(Crypter.stringToByteArray(m.getBody()), clientsMasterSecrets.get(c)));
		
		Message newm = new Message(body, m.getParams());
		
		if ((!handshaken.containsKey(c) || !handshaken.get(c)) && m.getMessageName() != null && m.getMessageName() != MessageName.Finished)
			handshakeMessages.get(c).add(newm);
		
		c.receiveSecureMessage(this, newm);
	}
	
	public void receiveMessage(Client c, Message m) throws CryptoException {
		if (!clients.contains(c))
			throw new CryptoException("The client isn't connected to the server!");
		
		if ((!handshaken.containsKey(c) || !handshaken.get(c)) && m.getMessageName() != null && m.getMessageName() != MessageName.Finished)
			handshakeMessages.get(c).add(m);
		
		parseMessage(c, m);
	}
	
	public void receiveSecureMessage(Client c, Message m) throws CryptoException {
		if (!clients.contains(c))
			throw new CryptoException("The client isn't connected to the server!");
		else if (!encryptedMode.containsKey(c) || !encryptedMode.get(c))
			throw new CryptoException("The handshake phase wasn't completed.");
		
		String body = Crypter.byteArrayToString(Crypter.decryptWithPassword(Crypter.stringToByteArray(m.getBody()), clientsMasterSecrets.get(c)));
		
		Message newm = new Message(body, m.getParams());
		
		if ((!handshaken.containsKey(c) || !handshaken.get(c)) && newm.getMessageName() != null && newm.getMessageName() != MessageName.Finished)
			handshakeMessages.get(c).add(newm);
		
		parseSecureMessage(c, m);
	}
	
	private void parseMessage(Client c, Message m) throws CryptoException {
		byte[] ciphertext;
		
		switch (m.getMessageName()) {
		case ClientHello:
			clientsRandomNumbers.put(c, (byte[])m.getParam(ParameterName.randomNumber));
			
			sendMessage(c, new Message(
					MessageName.ServerHello,
					new Parameter(ParameterName.randomNumber, RANDOM_NUMBER)));
			
			sendMessage(c, new Message(
					MessageName.Certificate,
					new Parameter(ParameterName.publicKey, publicKey)));
			
			sendMessage(c, new Message(
					MessageName.ServerHelloDone));
			break;
		case ClientKeyExchange:
			ciphertext = (byte[])m.getParam(ParameterName.preMasterSecret);
			clientsPreMasterSecrets.put(c, Crypter.decryptWithKey(ciphertext, Crypter.getPrivateKey(), Crypter.PRIVATE_KEY_ALGORITHM));
			break;
		case ChangeCipherSpec:
			encryptedMode.put(c, true);
			
			clientsMasterSecrets.put(c, Crypter.getMasterSecret(clientsPreMasterSecrets.get(c), clientsRandomNumbers.get(c), RANDOM_NUMBER));
			
			sendMessage(c, new Message(
					MessageName.ChangeCipherSpec));
			
			break;
		case Finished:
			byte[] receivedVerifyData = (byte[])m.getParam(ParameterName.verifyData);
			byte[] clientVerifyData = Crypter.pseudoRandomFunction(clientsMasterSecrets.get(c), Client.FINISHED_LABEL, Crypter.stringToByteArray(Message.getHash(handshakeMessages.get(c))));
			
			if (!Arrays.equals(receivedVerifyData, clientVerifyData))
				throw new CryptoException("The stream cannot be encrypted.");
			
			byte[] verifyData = Crypter.pseudoRandomFunction(clientsMasterSecrets.get(c), FINISHED_LABEL, Crypter.stringToByteArray(Message.getHash(handshakeMessages.get(c))));
			
			sendMessage(c, new Message(
					MessageName.Finished,
					new Parameter(ParameterName.verifyData, verifyData)));
			handshaken.put(c, true);
			break;
		default:
			break;
		}
	}
	
	private void parseSecureMessage(Client c, Message m) throws CryptoException {
		if (!handshaken.containsKey(c) || !handshaken.get(c))
			throw new CryptoException("The session wasn't authenticated.");
	}

}
