package com.github.fjf2002.keycloak.phpass;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class PHPassPasswordHashProvider implements PasswordHashProvider {
    private final int defaultIterationsLogBase2;
    private final String providerId;

    public PHPassPasswordHashProvider(final String providerId, final int defaultIterationsLogBase2) {
        this.providerId = providerId;
        this.defaultIterationsLogBase2 = defaultIterationsLogBase2;
    }

    @Override
    public boolean policyCheck(final PasswordPolicy policy, final PasswordCredentialModel credential) {
        final int defaultIterations = (1 << defaultIterationsLogBase2) + 1;

        final int policyHashIterations = policy.getHashIterations() == -1 ? defaultIterations : policy.getHashIterations();

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public String encode(String rawPassword, int iterationsLogBase2) {
        final int countLogBase2 = iterationsLogBase2 == -1 ? defaultIterationsLogBase2 : iterationsLogBase2;

        final String settings = PHPassTool.generateSettings(countLogBase2);

        return PHPassTool.hash(rawPassword, settings);
    }

    @Override
    public PasswordCredentialModel encodedCredential(final String rawPassword, final int iterationsLogBase2) {
        final int countLogBase2 = iterationsLogBase2 == -1 ? defaultIterationsLogBase2 : iterationsLogBase2;

        final String encodedPassword = encode(rawPassword, countLogBase2);

        // The salt is stored as part of the hashed password and there isn't much need for Keycloak to know about it
        final byte[] salt = new byte[0];

        return PasswordCredentialModel.createFromValues(providerId, salt, countLogBase2, encodedPassword);
    }

    @Override
    public void close() {
    }

    @Override
    public boolean verify(final String rawPassword, final PasswordCredentialModel credential) {
        return PHPassTool.checkPassword(rawPassword, credential.getPasswordSecretData().getValue());
    }
}
