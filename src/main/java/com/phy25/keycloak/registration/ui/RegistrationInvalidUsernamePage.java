package com.phy25.keycloak.registration.ui;

import org.keycloak.Config;
import org.keycloak.authentication.FormAuthenticator;
import org.keycloak.authentication.FormAuthenticatorFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import javax.ws.rs.core.Response;
import java.util.List;

public class RegistrationInvalidUsernamePage implements FormAuthenticator, FormAuthenticatorFactory {

	public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_PASSWORD_CONFIRM = "password-confirm";
    public static final String FIELD_EMAIL = "email";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_FIRST_NAME = "firstName";
    public static final String FIELD_LAST_NAME = "lastName";
    public static final String PROVIDER_ID = "registration-invalid-username-page-form";

    public Response render(FormContext context, LoginFormsProvider form) {
        return form.createRegistration();
    }

    public void close() {

    }

    public String getDisplayType() {
        return "Registration Page with Invalid Usernames";
    }

    public String getHelpText() {
        return "This is the controller for the registration page";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public FormAuthenticator create(KeycloakSession session) {
        return this;
    }

    public void init(Config.Scope config) {

    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public void postInit(KeycloakSessionFactory factory) {

    }

    public String getId() {
        return PROVIDER_ID;
    }
}
