package com.example.myoauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
				
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(Customizer.withDefaults())
			.anonymous().disable();
			
		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withUsername("alfser")
				.password("123456")
				.authorities("read")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

}

