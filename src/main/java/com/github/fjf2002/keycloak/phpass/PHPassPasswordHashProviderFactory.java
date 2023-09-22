package com.github.fjf2002.keycloak.phpass;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class PHPassPasswordHashProviderFactory implements PasswordHashProviderFactory {
	public static final String ID = "phpass";
	public static final int DEFAULT_ITERATIONS_LOG_BASE_2 = 16;

	@Override
	public PasswordHashProvider create(KeycloakSession session) {
		return new PHPassPasswordHashProvider(ID, DEFAULT_ITERATIONS_LOG_BASE_2);
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public void close() {
	}
}
