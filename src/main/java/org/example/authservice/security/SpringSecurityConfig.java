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
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // Register a DaoAuthenticationProvider bean for authentication using custom user details service and password encoding
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
            org.springframework.security.core.userdetails.UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService); // Custom user details service for authentication
        provider.setPasswordEncoder(bCryptPasswordEncoder); // BCrypt password encoder for password hashing
        return provider;
    }

    // Expose AuthenticationManager for use in other components (e.g., custom authentication endpoints)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        // AuthenticationManager is used to authenticate a user during login
        return configuration.getAuthenticationManager();
    }

    // Security filter chain for OAuth2 authorization server configuration
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
                                .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated() // All requests to authorization endpoints must be authenticated
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"), // Redirect to login page if not authenticated
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML) // Only for HTML requests
                        )
                );

        return http.build();
    }

    // Security filter chain for API endpoints with JWT authentication (for REST APIs)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .cors(Customizer.withDefaults()) // for CORS
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection for APIs
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self';"))
                )
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.deny())
                )

                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers(HttpMethod.POST, "/auth/signup").permitAll() // Public access to signup endpoint
                                .requestMatchers(HttpMethod.POST, "/auth/login").permitAll() // Public access to login endpoint
                                .requestMatchers("/auth/validate").permitAll() // Public access to validation endpoint
                                .requestMatchers(HttpMethod.POST, "/api/clients/register").permitAll() // Public access to client registration
                                .requestMatchers("/admin/**").hasRole("ADMIN") // Only ADMIN role can access /admin/** endpoints
                                .requestMatchers("/user/**").hasRole("USER") // Only USER role can access /user/** endpoints
                                .anyRequest().authenticated() // Any other requests must be authenticated
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())); // Configure OAuth2 resource server with JWT authentication

        return http.build();
    }

    // Bean to generate RSA keys for JWT signing and verification
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        // Generate RSA key pair. Typically, in a real-world scenario, keys are persisted and reused,
//        // but for development purposes, they are regenerated on each application restart.
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//
//        // Create RSAKey (JSON Web Key) from the public and private RSA keys
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString()) // Unique key ID for the JWT signing
//                .build();
//
//        // Create a JWKSet (JSON Web Key Set) and expose it as an immutable JWK source
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet); // Return read-only JWK source for JWT encoder/decoder
//    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }


    // Bean for decoding incoming JWT tokens
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        // Configure JWT decoder with the JWK source to decode the JWT tokens
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // Bean for encoding JWT tokens for outgoing responses
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // Configure JWT encoder with the JWK source to encode JWT tokens
        return new NimbusJwtEncoder(jwkSource);
    }

    // Bean for default authorization server settings
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // Return default settings for the authorization server. You can modify them as needed for custom configurations.
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*"); // Allow all origins for now
        configuration.addAllowedMethod("*");         // Allow all HTTP methods
        configuration.addAllowedHeader("*");         // Allow all headers
        configuration.setAllowCredentials(true);     // Allow credentials (cookies, authorization)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }




}
