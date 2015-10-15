package it.polimi.crypto;

import it.polimi.crypto.elements.Message;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Formatter;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Crypter {

	private static final Logger logger = LoggerFactory.getLogger(Crypter.class);
	
	public static final String PUBLIC_KEY_PATH = "rsa_public_key.pem";
	public static final String PUBLIC_KEY_ALGORITHM = "RSA/ECB/PKCS1Padding";
	private static RSAPublicKey publicKey = null;
	
	public static final String PRIVATE_KEY_PATH = "pkcs8_private_key.pem";
	public static final String PRIVATE_KEY_ALGORITHM = "RSA/ECB/PKCS1Padding";
	private static RSAPrivateKey privateKey = null;
	
	public static final String DEFAULT_HASH = "SHA-1";
	public static final String DEFAULT_HMAC = "HmacSHA1";
	
	public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	public static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
	
	public static final int DEFAULT_CHARS = 400*1024;
	
	public static final byte[] SALT = {
		11, 22, 33, 44, 55, 66, 77, 88
	};
	public static final byte[] IV = {
		0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 0, 10, 20, 30, 40, 50
	};

	public static String getKeyFromResource(String path) throws CryptoException {
		URL u = Crypter.class.getResource("/" + path);
		if (u == null)
			throw new CryptoException("File " + path + " not found.");

		StringBuilder sb = new StringBuilder();

		try (Scanner sc = new Scanner(Crypter.class.getResourceAsStream("/"
				+ path))) {
			while (sc.hasNextLine()) {
				String readLine = sc.nextLine();
				if (readLine.charAt(0) == '-') {
					continue;
				} else {
					sb.append(readLine);
					sb.append('\r');
				}
			}
		}

		if (sb.length() == 0)
			throw new CryptoException("The key read from " + path
					+ " is empty.");

		return sb.toString();
	}
	
	public static RSAPrivateKey getPrivateKey() throws CryptoException {
		String key = getKeyFromResource(PRIVATE_KEY_PATH);
		return getPrivateKey(key);
	}

	public static RSAPrivateKey getPrivateKey(String key) throws CryptoException {
		if (privateKey != null)
			return privateKey;
		
		try {
			byte[] buffer = Base64.decodeBase64(stringToByteArray(key));
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
	
			return privateKey;
		} catch (Exception e) {
			throw new CryptoException("Error while reading the private key.", e);
		}
	}

	public static RSAPublicKey getPublicKey() throws CryptoException {
		String key = getKeyFromResource(PUBLIC_KEY_PATH);
		return getPublicKey(key);
	}

	public static RSAPublicKey getPublicKey(String key) throws CryptoException {
		if (publicKey != null)
			return publicKey;
		
		try {
			byte[] buffer = Base64.decodeBase64(stringToByteArray(key));
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
			
			return publicKey;
		} catch (Exception e) {
			throw new CryptoException("Error while reading the public key.", e);
		}
	}

	static {
		try {
			Security.addProvider(new BouncyCastleProvider());
		} catch (Exception e) {
			logger.error("Error while initializing with the Bouncy Castle provider. Nothing will work :(.", e);
			System.exit(-1);
		}
		
		try {
	        Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
	        field.setAccessible(true);
	        field.set(null, java.lang.Boolean.FALSE);
	    } catch (Exception e) {
	        logger.error("Error while requesting a non-restricted environment.", e);
	        System.exit(-1);
	    }
	}
	
	public static byte[] stringToByteArray(String s) throws CryptoException {
		try {
			return s.getBytes("UTF-8");
		} catch (Exception e) {
			throw new CryptoException("The string couldn't be considered as UTF-8.", e);
		}
	}
	
	public static String byteArrayToString(byte[] b) throws CryptoException {
		try {
			return new String(b, "UTF-8");
		} catch (Exception e) {
			throw new CryptoException("The block of bytes couldn't be considered as UTF-8.", e);
		}
	}

	public static byte[] encryptWithKey(byte[] text, Key key, String algorithm)
			throws CryptoException {
		try {
			Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, key);
	
			byte[] res = cipher.doFinal(text);
			return res;
		} catch (Exception e) {
			throw new CryptoException("Error while encrypting the message.", e);
		}
	}

	public static byte[] decryptWithKey(byte[] ciphertext, Key key,
			String algorithm) throws CryptoException {
		try {
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, key);
	
			byte[] res = cipher.doFinal(ciphertext);
			return res;
		} catch (Exception e) {
			throw new CryptoException("Error while decrypting the message.", e);
		}
	}
	
	public static String getHash(String text) throws CryptoException {
		MessageDigest md = null;
	    try {
	        md = MessageDigest.getInstance(DEFAULT_HASH);
	    }
	    catch(NoSuchAlgorithmException e) {
	        throw new CryptoException("Algorithm not found.", e);
	    } 
	    
	    byte[] hashed = md.digest(stringToByteArray(text));
	    
	    String result = "";
	    try (Formatter formatter = new Formatter()) {
		    for (byte b : hashed)
		        formatter.format("%02x", b);
		    result = formatter.toString();
	    }
	    return result;
	}
	
	public static byte[] getHash(byte[] secret, byte[] text) throws CryptoException {
		SecretKeySpec keySpec = new SecretKeySpec(
		        secret,
		        DEFAULT_HMAC);
		
		try {
			Mac mac = Mac.getInstance(DEFAULT_HMAC);
			mac.init(keySpec);
			byte[] result = mac.doFinal(text);
			result = Base64.encodeBase64(result);
			return result;
		} catch (Exception e) {
			throw new CryptoException("Error while getting the HMAC.", e);
		}
	}
	
	public static byte[] pseudoRandomFunction(byte[] secret, String label, byte[] seed) throws CryptoException {
		return getHash(secret, concatenate(stringToByteArray(label), seed));
	}
	
	public static byte[] concatenate(byte[]... arrays) throws CryptoException {
		if (arrays.length <= 0)
			return new byte[0];
		else if (arrays.length == 1)
			return arrays[0];
		
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			for (byte[] array : arrays)
				out.write(array);
			out.flush();
			return out.toByteArray();
		} catch (Exception e) {
			throw new CryptoException("Error while concatenating the arrays.", e);
		}
	}
	
	public static byte[] getMasterSecret(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom) throws CryptoException {
		final String label = "master secret";
		
		byte[] masterSecret = pseudoRandomFunction(preMasterSecret, label, concatenate(clientRandom, serverRandom));
		
		return masterSecret;
	}
	
	public static byte[] encryptWithPassword(byte[] text, byte[] password) throws CryptoException {
		try {
			/* Derive the key, given password and salt. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
			KeySpec spec = new PBEKeySpec(byteArrayToString(password).toCharArray(), SALT, 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "PBEWithHmacSHA1AndDESede"); //"AES");
			
			Cipher encrypter = Cipher.getInstance(CIPHER_ALGORITHM);
			encrypter.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(IV));
			
			/* Encrypt the message. */
			return Base64.encodeBase64(encrypter.doFinal(text));
		} catch (Exception e) {
			throw new CryptoException("Error while encrypting with password.", e);
		}
	}
	
	public static byte[] decryptWithPassword(byte[] ciphertext, byte[] password) throws CryptoException {
		try {
			/* Derive the key, given password and salt. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
			KeySpec spec = new PBEKeySpec(byteArrayToString(password).toCharArray(), SALT, 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "PBEWithHmacSHA1AndDESede"); //"AES");
			
			Cipher decrypter = Cipher.getInstance(CIPHER_ALGORITHM);
			decrypter.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(IV));
			
			/* Decrypt the message, given derived key and initialization vector. */
			return decrypter.doFinal(Base64.decodeBase64(ciphertext));
		} catch (Exception e) {
			throw new CryptoException("Error while decrypting with password.", e);
		}
	}
	
	public static long timeRunning(int chars) throws CryptoException {
		return timeRunning(chars, null);
	}
	
	public static long timeRunning(int chars, PrintStream out) throws CryptoException {
		long init = System.currentTimeMillis();

		Client c = new Client();
		Server s = new Server();
		
		c.connect(s);
		c.handshake();
		c.sendSecureMessage(new Message(RandomStringUtils.randomAlphanumeric(chars)));
		c.disconnect();

		long end = System.currentTimeMillis();
		long duration = end - init;
		
		if (out != null) {
			SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss:SSS");
			
			out.println(dateFormat.format(new Date(init)) + "\t" + dateFormat.format(new Date(end)) + "\t" + duration);
		}
		
		return duration;
	}

	public static String durationToString(long duration) {
		String actualDuration = "";
		{
			int res = (int) TimeUnit.MILLISECONDS.toSeconds(duration);
			if (res > 60 * 60) {
				actualDuration += (res / (60 * 60)) + " h ";
				res = res % (60 * 60);
			}
			if (res > 60) {
				actualDuration += (res / 60) + " m ";
				res = res % 60;
			}
			actualDuration += res + " s";
		}

		return actualDuration;
	}
	
	static {
		try {
			timeRunning(DEFAULT_CHARS);
			timeRunning(DEFAULT_CHARS);
			timeRunning(DEFAULT_CHARS);
		} catch (Exception e) {
			logger.error("Error while initializing the test.", e);
			System.exit(-1);
		}
	}
	
	public static List<Long> doTests(
			int chars, int tests,
			int sleepBetweenMin, int sleepBetweenMax,
			int testsMin, int testsMax,
			int sleepBetweenLong, int testsAverage) throws CryptoException {
		return doTests(chars, tests, sleepBetweenMin, sleepBetweenMax, testsMin, testsMax, sleepBetweenLong, testsAverage, System.out);
	}
	
	public static List<Long> doTests(
			int chars, int tests,
			int sleepBetweenMin, int sleepBetweenMax,
			int testsMin, int testsMax,
			int sleepBetweenLong, int testsAverage,
			PrintStream out) throws CryptoException {
		List<Long> res = new ArrayList<Long>();

		if (tests <= 0)
			return res;
		
		if (sleepBetweenMin < 0)
			sleepBetweenMin = 0;
		if (sleepBetweenMax < sleepBetweenMin)
			sleepBetweenMax = sleepBetweenMin;
		if (sleepBetweenLong < 2*sleepBetweenMax)
			sleepBetweenLong = 2*sleepBetweenMax;
		if (testsMin < 1)
			testsMin = 1;
		if (testsMax < testsMin)
			testsMax = testsMin;
		if (testsAverage < 1)
			testsAverage = 1;
		
		long time;
		
		int count = 0;
		int lastRandom = nextRandom(testsMin, testsMax);
		int longWait = sleepBetweenLong;
		boolean criticPhase = false;
		
		double averageTime = -1;
		
		for (int i = 1; i <= tests - 1; ++i) {
			time = timeRunning(chars, out);
			res.add(time);
			count++;
			if (i >= testsAverage) {
				if (averageTime <= 0) {
					averageTime = 0;
					for (long l : res)
						averageTime += l;
					averageTime /= res.size();
				}
				if (time >= 2*averageTime) {
					logger.info("Critic phase!");
					criticPhase = true;
					longWait = sleepBetweenLong;
					try {
						Thread.sleep(longWait);
						count = 0;
					} catch (InterruptedException e) {
						logger.error("Error while waiting between tests.", e);
					}
				} else if (criticPhase) {
					longWait /= 2;
					try {
						Thread.sleep(longWait);
						count = 0;
					} catch (InterruptedException e) {
						logger.error("Error while waiting between tests.", e);
					}
				}
				if (longWait <= sleepBetweenMax)
					criticPhase = false;
			}
			if (count >= lastRandom)
				try {
					Thread.sleep(nextRandom(sleepBetweenMin, sleepBetweenMax));
					lastRandom = nextRandom(testsMin, testsMax);
					count = 0;
				} catch (InterruptedException e) {
					logger.error("Error while waiting between tests.", e);
				}
		}
		
		time = timeRunning(chars, out);
		res.add(time);
		
		return res;
	}
	
	private static final Random rnd = new Random(UUID.randomUUID().getMostSignificantBits());
	
	private static int nextRandom(int min, int max) {
		return rnd.nextInt(max + 1 - min) + min;
	}
	
	public static List<Long> doTestsForDuration(
			int chars, int duration,
			int sleepBetweenMin, int sleepBetweenMax,
			int testsMin, int testsMax,
			int sleepBetweenLong, int testsAverage,
			PrintStream out) throws CryptoException {
		List<Long> res = new ArrayList<Long>();
		
		if (duration <= 0)
			return res;
		
		if (sleepBetweenMin < 0)
			sleepBetweenMin = 0;
		if (sleepBetweenMax < sleepBetweenMin)
			sleepBetweenMax = sleepBetweenMin;
		if (sleepBetweenLong < 2*sleepBetweenMax)
			sleepBetweenLong = 2*sleepBetweenMax;
		if (testsMin < 1)
			testsMin = 1;
		if (testsMax < testsMin)
			testsMax = testsMin;
		if (testsAverage < 1)
			testsAverage = 1;
		
		long init = System.currentTimeMillis();
		
		long time;
		
		int count = 0;
		int lastRandom = nextRandom(testsMin, testsMax);
		int longWait = sleepBetweenLong;
		boolean criticPhase = false;
		
		double averageTime = -1;
		int i = 1;
		
		while ((System.currentTimeMillis() - init) < duration*1000) {
			time = timeRunning(chars, out);
			res.add(time);
			count++;
			if (i >= testsAverage) {
				if (averageTime <= 0) {
					averageTime = 0;
					for (long l : res)
						averageTime += l;
					averageTime /= res.size();
				}
				if (time >= 2*averageTime) {
					logger.info("Critic phase!");
					criticPhase = true;
					longWait = sleepBetweenLong;
					try {
						Thread.sleep(longWait);
						count = 0;
					} catch (InterruptedException e) {
						logger.error("Error while waiting between tests.", e);
					}
				} else if (criticPhase) {
					longWait /= 2;
					try {
						Thread.sleep(longWait);
						count = 0;
					} catch (InterruptedException e) {
						logger.error("Error while waiting between tests.", e);
					}
				}
				if (longWait <= sleepBetweenMax)
					criticPhase = false;
			}
			if (count >= lastRandom)
				try {
					Thread.sleep(nextRandom(sleepBetweenMin, sleepBetweenMax));
					lastRandom = nextRandom(testsMin, testsMax);
					count = 0;
				} catch (InterruptedException e) {
					logger.error("Error while waiting between tests.", e);
				}
			i++;
		}
		
		return res;
	}

}
