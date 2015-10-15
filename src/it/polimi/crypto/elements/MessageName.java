package it.polimi.crypto.elements;

public enum MessageName {
	ClientHello("ClientHello"), ServerHello("ServerHello"), Certificate("Certificate"), ServerHelloDone("ServerHelloDone"),
	ClientKeyExchange("ClientKeyExchange"), ChangeCipherSpec("ChangeCipherSpec"), Finished("Finished");
		
	private String name;
	
	private MessageName(String name) {
		this.name = name;
	}
	
	public static MessageName getByName(String name) {
		MessageName[] values = values();
		for (MessageName m : values)
			if (m.name.equals(name))
				return m;
		return null;
	}
	
	public String getName() {
		return name;
	}
}
