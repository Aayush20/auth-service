package org.example.authservice.security.dtos;
import java.util.List;
public class ClientRegistrationDTO {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private List<String> clientAuthenticationMethods;
    private List<String> authorizationGrantTypes;
    private List<String> redirectUris;
    private List<String> postLogoutRedirectUris;
    private List<String> scopes;
    private String clientSettings;  // These might be JSON strings
    private String tokenSettings;   // or any custom format you prefer

    // Getters and setters

    public String getClientId() {
        return clientId;
    }
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    public String getClientSecret() {
        return clientSecret;
    }
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
    public String getClientName() {
        return clientName;
    }
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
    public List<String> getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }
    public void setClientAuthenticationMethods(List<String> clientAuthenticationMethods) {
        this.clientAuthenticationMethods = clientAuthenticationMethods;
    }
    public List<String> getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }
    public void setAuthorizationGrantTypes(List<String> authorizationGrantTypes) {
        this.authorizationGrantTypes = authorizationGrantTypes;
    }
    public List<String> getRedirectUris() {
        return redirectUris;
    }
    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }
    public List<String> getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }
    public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
    }
    public List<String> getScopes() {
        return scopes;
    }
    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }
    public String getClientSettings() {
        return clientSettings;
    }
    public void setClientSettings(String clientSettings) {
        this.clientSettings = clientSettings;
    }
    public String getTokenSettings() {
        return tokenSettings;
    }
    public void setTokenSettings(String tokenSettings) {
        this.tokenSettings = tokenSettings;
    }
}

