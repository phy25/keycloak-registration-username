package com.phy25.keycloak.registration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.broker.provider.util.SimpleHttp;
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

public class RegistrationUsername implements FormAction, FormActionFactory {

    private static final Logger logger = Logger.getLogger(RegistrationUsername.class);

    public static final String USERNAME_REGEX = "profile.username.regex";
	public static final String INVALID_USERNAMES = "profile.username.invalid";
    public static final String HOOK_URL = "profile.username.hook-url";
    public static final String PROVIDER_ID = "registration-username-action";
    
    public String getHelpText() {
        return "Validates username. Checks if username is in the list of invalid usernames. " +
                "Relies on Registration User Creation.";
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
        property.setLabel("Invalid Username");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of invalid usernames, separated by comma");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(HOOK_URL);
        property.setLabel("Hook GET URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("?username=[username]&email=[email]");
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
        
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        if(Validation.isBlank(username)){
        	errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.MISSING_USERNAME));
        }else{
        	Map<String, String> usernameConfig = context.getAuthenticatorConfig().getConfig();
        	String invalidUsernameString = usernameConfig.get(INVALID_USERNAMES);
        	if (invalidUsernameString != null){
            	List<String> invalidUsernames = Arrays.asList(invalidUsernameString.toLowerCase().split(","));
        	
                if(invalidUsernames.contains(username.toLowerCase())){
                    eventError = Errors.INVALID_USER_CREDENTIALS;
                    context.getEvent().detail(Details.USERNAME, username);
                    errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, RegistrationUsernameConstants.USER_NAME_NOT_AVAILABLE));
                }
        	}

            String usernameRegex = usernameConfig.get(USERNAME_REGEX);
			Pattern pattern = Pattern.compile(usernameRegex);
			Matcher matcher = pattern.matcher(username);
	        if(!matcher.matches()){
	        	eventError = Errors.INVALID_USER_CREDENTIALS;
	     	    context.getEvent().detail(Details.USERNAME, username);
	            errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, RegistrationUsernameConstants.INVALID_USER_NAME_CHARACTERS));
	        }

            // hook check
            String baseUrl = usernameConfig.get(HOOK_URL);
            if (baseUrl != null && !("".equals(baseUrl))) {
                UriBuilder urlBuild = UriBuilder.fromUri(baseUrl)
                        .queryParam("username", username);
                String url = urlBuild.build().toString();
                try {
                    String resp = SimpleHttp.doGet(url, context.getSession()).asString();
                    if ("yes".equals(resp)) {
                        logger.warn("Matched hook request: " + url);
                        eventError = Errors.INVALID_USER_CREDENTIALS;
                        context.getEvent().detail(Details.USERNAME, username);
                        errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, RegistrationUsernameConstants.REGISTRATION_PREVENTED_EXTERNAL));
                    }
                } catch (Exception e) {
                    logger.warn("Failed hook request: " + url, e);
                }
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
        // complete
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
        return "Username Validation in Registration Form";
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
