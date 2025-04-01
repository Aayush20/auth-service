package org.example.authservice.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;


//Filter Chain is the order of the filters that are applied to the incoming request to deny or accept the request.

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // Explicitly register a DaoAuthenticationProvider bean
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
            org.springframework.security.core.userdetails.UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService); // our custom user details service
        provider.setPasswordEncoder(bCryptPasswordEncoder); // BCrypt for password matching
        return provider;
    }

    // Expose the AuthenticationManager if necessary (helps in some controllers or custom authentication endpoints)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }


//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//
//        http
//                // If you're building a REST API, consider disabling CSRF
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(authorize ->
//                        authorize
//                                .requestMatchers("/api/signup", "/auth/signup", "/auth/validate").permitAll()
//                                .anyRequest().authenticated()
//                                // Example: Permit public access to signup endpoint but restrict client registration
////                                .requestMatchers("/api/signup").permitAll()
////                                .requestMatchers("/api/clients/register").permitAll()
//                                // Permit all for demonstration; adjust as needed
//                )
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
@Bean
@Order(2)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
        throws Exception {

    http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(authorize ->
                    authorize
                            // Permit POST to /auth/signup and /auth/validate, and any GET if necessary.
                            .requestMatchers(HttpMethod.POST, "/auth/signup").permitAll()
                            .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                            .requestMatchers("/auth/validate").permitAll()
                            .requestMatchers(HttpMethod.POST, "/api/clients/register").permitAll()
                            .anyRequest().authenticated()
            )
            // For REST API responses, use httpBasic() and disable formLogin
//            .httpBasic(Customizer.withDefaults())
//            .exceptionHandling(exception ->
//                    exception.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//            );
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

    return http.build();
}



    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    //The current JWK source regenerates a new RSA key pair every time the application starts.
    //This is typical for a development or test setup, but in a production environment,
    // you might want to externalize or persist the key material so that tokens remain verifiable across restarts.

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


    //permit all - allows all request vs authenticated - allows only authenticated request
//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                                //.requestMatchers("/api/signup", "/error").permitAll()
//                                //.requestMatchers("/login/**").authenticated() // only authenticated users can access /products/**
//                       .anyRequest().permitAll() // all other requests are allowed
//                )
//                // Form login handles the redirect to the login page from the
//                // authorization server filter chain
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }

    //Spring Security provides a default implementation of UserDetailsService called InMemoryUserDetailsManager
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.builder()
//                .username("user")
//                .password(bCryptPasswordEncoder.encode("password"))
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

    // @Bean
    // public RegisteredClientRepository registeredClientRepository() {
    // 	RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
    // 			.clientId("oidc-client")
    // 			.clientSecret("{noop}secret")
    // 			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    // 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    // 			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    // 			.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
    // 			.postLogoutRedirectUri("http://127.0.0.1:8080/")
    // 			.scope(OidcScopes.OPENID)
    // 			.scope(OidcScopes.PROFILE)
    // 			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
    // 			.build();

    // 	return new InMemoryRegisteredClientRepository(oidcClient);
    // }
}

