package com.keycloak.custom.extensions.ui;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import com.keycloak.custom.extensions.misc.RegistrationInvalidUsernameConstants;

public class RegistrationInvalidUsernameProfile implements FormAction, FormActionFactory {
	
	public static final String USERNAME_REGEX = "profile.username.regex";
	public static final String INVALID_USERNAMES = "profile.username.invalid";
    public static final String PROVIDER_ID = "registration-invalid-username-profile-action";
    
    public String getHelpText() {
        return "Validates email and username. Checks if username is in the list of invalid usernames";
    }
    
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(USERNAME_REGEX);
        property.setLabel("Username Pattern");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Regex pattern");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(INVALID_USERNAMES);
        property.setLabel("Invalid Usernames");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of invalid usernames");
        CONFIG_PROPERTIES.add(property);
    }

    public List<ProviderConfigProperty> getConfigProperties() {
    	return CONFIG_PROPERTIES;
    }

    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    
        List<FormMessage> errors = new ArrayList<FormMessage>();
        
        context.getEvent().detail(Details.REGISTER_METHOD, "form");
        String eventError = Errors.INVALID_REGISTRATION;
        
        if (Validation.isBlank(formData.getFirst((RegistrationInvalidUsernamePage.FIELD_FIRST_NAME)))) {
            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_FIRST_NAME, Messages.MISSING_FIRST_NAME));
        }

        if (Validation.isBlank(formData.getFirst((RegistrationInvalidUsernamePage.FIELD_LAST_NAME)))) {
            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_LAST_NAME, Messages.MISSING_LAST_NAME));
        }

        String email = formData.getFirst(Validation.FIELD_EMAIL);
        boolean emailValid = true;
        if (Validation.isBlank(email)) {
            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_EMAIL, Messages.MISSING_EMAIL));
            emailValid = false;
        } else if (!Validation.isEmailValid(email)) {
            context.getEvent().detail(Details.EMAIL, email);
            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_EMAIL, Messages.INVALID_EMAIL));
            emailValid = false;
        }

        if (emailValid && !context.getRealm().isDuplicateEmailsAllowed() && context.getSession().users().getUserByEmail(email, context.getRealm()) != null) {
            eventError = Errors.EMAIL_IN_USE;
            context.getEvent().detail(Details.EMAIL, email);
            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_EMAIL, Messages.EMAIL_EXISTS));
        }
        
        String username = formData.getFirst(RegistrationInvalidUsernamePage.FIELD_USERNAME);
        if(Validation.isBlank(username)){
        	errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_USERNAME, Messages.MISSING_USERNAME));        	
        }else{
        	Map<String, String> usernameConfig = context.getAuthenticatorConfig().getConfig();
        	String usernameRegex = usernameConfig.get(USERNAME_REGEX);
        	List<String> invalidUsernames = Arrays.asList(usernameConfig.get(INVALID_USERNAMES).toLowerCase().split(","));
        	
        	if(invalidUsernames.contains(username.toLowerCase())){
	        	eventError = Errors.INVALID_USER_CREDENTIALS;
	     	    context.getEvent().detail(Details.USERNAME, username);
	            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_USERNAME, RegistrationInvalidUsernameConstants.USER_NAME_NOT_AVAILABLE));
	        }
			Pattern pattern = Pattern.compile(usernameRegex);
			Matcher matcher = pattern.matcher(username);
	        if(!matcher.matches()){
	        	eventError = Errors.INVALID_USER_CREDENTIALS;
	     	    context.getEvent().detail(Details.USERNAME, username);
	            errors.add(new FormMessage(RegistrationInvalidUsernamePage.FIELD_USERNAME, RegistrationInvalidUsernameConstants.INVALID_USER_NAME_CHARACTERS));
	        }
        	
		}
        
        if (errors.size() > 0) {      	
            context.error(eventError);
            context.validationError(formData, errors);
            return;

        } else {
            context.success();
        }
    }

    public void success(FormContext context) {
        UserModel user = context.getUser();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        user.setFirstName(formData.getFirst(RegistrationInvalidUsernamePage.FIELD_FIRST_NAME));
        user.setLastName(formData.getFirst(RegistrationInvalidUsernamePage.FIELD_LAST_NAME));
        user.setEmail(formData.getFirst(RegistrationInvalidUsernamePage.FIELD_EMAIL));
        user.setUsername(formData.getFirst(RegistrationInvalidUsernamePage.FIELD_USERNAME));
    }

    public void buildPage(FormContext context, LoginFormsProvider form) {
        // complete
    }

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public void close() {

    }

    public String getDisplayType() {
        return "Profile Validation with Invalid Usernames";
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
        return true;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    
    public FormAction create(KeycloakSession session) {
        return this;
    }

    public void init(Config.Scope config) {
    	
    }

    public void postInit(KeycloakSessionFactory factory) {

    }

    public String getId() {
        return PROVIDER_ID;
    }
}
