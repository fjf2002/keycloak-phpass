package com.github.fjf2002.keycloak.phpass;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

class PHPassPasswordHashProviderTest {
	private final int iterations = 10;
	private final String id = "phpass";
	private final PHPassPasswordHashProvider provider = new PHPassPasswordHashProvider();

	@Test
	void shouldVerifyPHash() {
		final String rawPassword = "password";
		
		final PasswordCredentialModel model = PasswordCredentialModel.createFromValues(id, new byte[0], iterations,
				"$P$5ZDzPE45Ci.QxPaPz.03z6TYbakcSQ0");

		assertTrue(provider.verify(rawPassword, model));
	}
	
	@Test
	void shouldVerifyHHash() {
		final String rawPassword = "pa$$w0rd";
		
		final PasswordCredentialModel model = PasswordCredentialModel.createFromValues(id, new byte[0], iterations,
				"$H$8ZDzPE45CwvreDvYyUho6FIz5xpsUS/");

		assertTrue(provider.verify(rawPassword, model));
	}
	
	@Test
	void shouldVerifyHashWithUmlaut() {
		final String rawPassword = "passwörd";
		
		final PasswordCredentialModel model = PasswordCredentialModel.createFromValues(id, new byte[0], iterations,
				"$P$DN0nNIzQPadEL2VcdVzVj5fk8MBaLP1");

		assertTrue(provider.verify(rawPassword, model));
	}	
}
