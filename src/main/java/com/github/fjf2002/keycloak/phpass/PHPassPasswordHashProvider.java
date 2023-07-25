package com.github.fjf2002.keycloak.phpass;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class PHPassPasswordHashProvider implements PasswordHashProvider {

	@Override
	public boolean policyCheck(final PasswordPolicy policy, final PasswordCredentialModel credential) {
		throw new UnsupportedOperationException("PHPass password policies are not supported.");
	}

	@Override
	public String encode(String rawPassword, int iterations) {
		throw new UnsupportedOperationException("PHPass password encoding is not supported.");
	}
	
	@Override
	public PasswordCredentialModel encodedCredential(final String rawPassword, final int iterations) {
		throw new UnsupportedOperationException("PHPass password encoding is not supported.");
	}

	@Override
	public void close() {
	}

	@Override
	public boolean verify(final String rawPassword, final PasswordCredentialModel credential) {
		return PHPassTool.checkPassword(rawPassword, credential.getPasswordSecretData().getValue());
	}
}
