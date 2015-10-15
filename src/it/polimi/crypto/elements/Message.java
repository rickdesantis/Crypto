package it.polimi.crypto.elements;

import it.polimi.crypto.Crypter;
import it.polimi.crypto.CryptoException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Message {
	
	private String body;
	private Map<ParameterName, Object> params;
	
	public static final byte[] FILLING = {
		 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
		31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
		51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
		61, 62, 63, 64, 65, 66, 67, 68, 69, 70
		};

	public Message(String body, Parameter... ps) {
		this.body = body;
		this.params = new HashMap<ParameterName, Object>();
		addParam(ParameterName.filling, FILLING);
		for (Parameter p : ps)
			addParam(p.name, p.value);
	}
	
	public Message(MessageName msg, Parameter... ps) {
		this(msg.getName(), ps);
	}
	
	public Message(String body, Map<ParameterName, Object> params) {
		this(body, new Parameter[0]);
		for (ParameterName name : params.keySet())
			addParam(name, params.get(name));
	}
	
	public void addParam(ParameterName name, Object value) {
		params.put(name, value);
	}
	
	public Object getParam(ParameterName name) {
		return params.get(name);
	}
	
	public Map<ParameterName, Object> getParams() {
		return params;
	}
	
	public String getBody() {
		return body;
	}
	
	public MessageName getMessageName() {
		return MessageName.getByName(body);
	}
	
	public static class Parameter {
		public ParameterName name;
		public Object value;
		public Parameter(ParameterName name, Object value) {
			this.name = name;
			this.value = value;
		}
	}
	
	public static String getHash(List<Message> msgs) throws CryptoException {
		StringBuilder sb = new StringBuilder();
		for (Message m : msgs) {
			sb.append(m.getBody());
			Map<ParameterName, Object> params = m.getParams(); 
			for (ParameterName n : params.keySet()) {
				sb.append(n.getName());
				sb.append(params.get(n));
			}
		}
		
		return Crypter.getHash(sb.toString());
	}

}
