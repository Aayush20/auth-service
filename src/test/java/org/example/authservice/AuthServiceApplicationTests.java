package org.example.authservice;

import org.example.authservice.models.User;
import org.example.authservice.repositories.UserRepository;
import org.example.authservice.security.repositories.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.UUID;

@SpringBootTest
class AuthServiceApplicationTests {

    @Autowired
    private JpaRegisteredClientRepository  registeredClientRepository;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Test
    void contextLoads() {
    }

//    @Test
//    public void userDetailsService() {
//        User user = new User();
//		user.setName("Aayush");
//		user.setHashedPassword(bCryptPasswordEncoder.encode("password"));
//		userRepository.save(user);
//    }

}
