package it.polimi.crypto.elements;

public enum ParameterName {
	preMasterSecret("preMasterSecret"), randomNumber("randomNumber"), publicKey("publicKey"), verifyData("verifyData"), filling("filling");
	
	private String name;
	
	private ParameterName(String name) {
		this.name = name;
	}
	
	public static ParameterName getByName(String name) {
		ParameterName[] values = values();
		for (ParameterName m : values)
			if (m.name.equals(name))
				return m;
		return null;
	}
	
	public String getName() {
		return name;
	}
}
