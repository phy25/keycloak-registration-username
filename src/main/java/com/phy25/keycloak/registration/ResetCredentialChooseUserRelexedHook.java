package com.phy25.keycloak.registration;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ResetCredentialChooseUserRelexedHook implements Authenticator, AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(ResetCredentialChooseUserRelexedHook.class);

    public static final String ENABLE_INVALID_PROMPT = "resetcred.choose.prompt";
    public static final String HOOK_URL = "resetcred.choose.hook-url";
    public static final String PROVIDER_ID = "phy25-reset-creds-choose-rh";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ENABLE_INVALID_PROMPT);
        property.setLabel("Enable Invalid Prompt");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("This may allow username guessing");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(HOOK_URL);
        property.setLabel("Hook GET URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("?username=[username/email]");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String existingUserId = context.getAuthenticationSession().getAuthNote(AbstractIdpAuthenticator.EXISTING_USER_INFO);
        if (existingUserId != null) {
            UserModel existingUser = AbstractIdpAuthenticator.getExistingUser(context.getSession(), context.getRealm(), context.getAuthenticationSession());

            logger.debugf("Forget-password triggered when reauthenticating user after first broker login. Skipping reset-credential-choose-user screen and using user '%s' ", existingUser.getUsername());
            context.setUser(existingUser);
            context.success();
            return;
        }

        String actionTokenUserId = context.getAuthenticationSession().getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
        if (actionTokenUserId != null) {
            UserModel existingUser = context.getSession().users().getUserById(actionTokenUserId, context.getRealm());

            // Action token logics handles checks for user ID validity and user being enabled

            logger.debugf("Forget-password triggered when reauthenticating user after authentication via action token. Skipping reset-credential-choose-user screen and using user '%s' ", existingUser.getUsername());
            context.setUser(existingUser);
            context.success();
            return;
        }

        Response challenge = context.form().createPasswordReset();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        EventBuilder event = context.getEvent();
        String eventError = null;
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst("username");
        if (username == null || username.isEmpty()) {
            event.error(Errors.USERNAME_MISSING);
            Response challenge = context.form()
                    .setError(Messages.MISSING_USERNAME)
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        username = username.trim();

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserByUsername(username, realm);
        if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
            user =  context.getSession().users().getUserByEmail(username, realm);
        }

        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        Map<String, String> usernameConfig = context.getAuthenticatorConfig().getConfig();
        String enablePrompt = usernameConfig.get(ENABLE_INVALID_PROMPT);

        // we would prompt users here
        if (user == null) {
            event.clone()
                    .detail(Details.USERNAME, username)
                    .error(Errors.USER_NOT_FOUND);

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
                        eventError = RegistrationUsernameConstants.RESET_PASSWORD_PREVENTED_EXTERNAL;
                    }
                } catch (Exception e) {
                    logger.warn("Failed hook request: " + url, e);
                }
            }

            context.clearUser();
            if ("true".equals(enablePrompt) && eventError == null) {
                eventError = Messages.INVALID_USER;
            }
        } else if (!user.isEnabled()) {
            event.clone()
                    .detail(Details.USERNAME, username)
                    .user(user).error(Errors.USER_DISABLED);
            context.clearUser();
            if ("true".equals(enablePrompt)) {
                eventError = Messages.ACCOUNT_DISABLED;
            }
        } else {
            context.setUser(user);
        }

        if (eventError != null) {
            LoginFormsProvider challengeForm = context.form();
            challengeForm.setError(eventError);
            context.forceChallenge(challengeForm.createPasswordReset());
            return;
        }
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Choose User (Relexed Hook)";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Choose a user to reset credentials for (relexed + hook)";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
