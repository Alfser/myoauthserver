package com.example.myoauthserver.config;

import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.myoauthserver.config.keys.KeyManager;
import com.example.myoauthserver.config.properties.AuthProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class AuthServerConfig {

    private final KeyManager keyManager;

    @Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> { 
			OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
			JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();

			return new OidcUserInfo(principal.getToken().getClaims());
		};

		authorizationServerConfigurer
			.oidc((oidc) -> oidc
				.userInfoEndpoint((userInfo) -> userInfo
					.userInfoMapper(userInfoMapper) 
				)
			);

		http
			.securityMatcher(endpointsMatcher)
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt) 
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			)
			.apply(authorizationServerConfigurer); 

		return http.build();
	}

    @Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder, JdbcTemplate jdbcTemplate) {
		// RegisteredClient defaultClient = RegisteredClient.withId(UUID.randomUUID().toString())
		// 		.clientId("client-openid")
		// .clientSecret(encoder.encode("secret"))
		// 		.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
		// 		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		// 		.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        //         .redirectUri("https://spring.io/auth")
				// .scope(OidcScopes.OPENID)
		// 		.tokenSettings(
		// 			TokenSettings.builder()
		// 			.accessTokenTimeToLive(Duration.ofMinutes(15))
		// 			.refreshTokenTimeToLive(Duration.ofHours(5))
		// 			.reuseRefreshTokens(false)
		// 			.build()
		// 		)
		// 		.clientSettings(
		// 			ClientSettings.builder()
		// 			.requireAuthorizationConsent(true)
		// 			.build()
		// 		).build();

		// 		RegisteredClient backendClient = RegisteredClient.withId(UUID.randomUUID().toString())
		// 		.clientId("backend")
		// 		.clientSecret(encoder.encode("backendsecret"))
		// 		.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
		// 		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        //         .redirectUri("http://spring.io/auth")
		// 		.scope("user:read")
		// 		.scope("user:write")
		// 		.tokenSettings(
		// 			TokenSettings.builder()
		// 			.accessTokenTimeToLive(Duration.ofHours(1))
		// 			.build()
		// 		)
		// 		.clientSettings(
		// 			ClientSettings.builder()
		// 			.requireAuthorizationConsent(false)
		// 			.build()
		// 		).build();
		
		JdbcRegisteredClientRepository clientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		// clientRepository.save(defaultClient);
		// clientRepository.save(backendClient);
		return clientRepository;
	}


	@Bean
	public OAuth2AuthorizationService auth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository clientRepository){
		return new JdbcOAuth2AuthorizationService(
			jdbcOperations,
			clientRepository
		);
	}

	@Bean
	public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(
		JdbcOperations jdbcOperations,
		RegisteredClientRepository clientRepository
		){
		return new JdbcOAuth2AuthorizationConsentService(
			jdbcOperations, 
			clientRepository
		);
	}

    @Bean
	public AuthorizationServerSettings authorizationServerSettings(AuthProperties authProperties) {
		return AuthorizationServerSettings.builder()
				.issuer(authProperties.getProviderUriIssuer())
				.build();
	}

    @Bean
	public JWKSource<SecurityContext> jwkSource() {
		JWKSet jwkSet = new JWKSet(keyManager.rsaKey());
		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}	
}
