package com.example.myoauthserver.config;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

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
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(
					new LoginUrlAuthenticationEntryPoint("/login"))
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

    @Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient defaultClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://spring.io/auth")
				.scope(OidcScopes.PROFILE)
				.scope(OidcScopes.OPENID)
				.scope("user:read")
				.tokenSettings(
					TokenSettings.builder()
					.accessTokenTimeToLive(Duration.ofMinutes(15))
					.refreshTokenTimeToLive(Duration.ofHours(5))
					.reuseRefreshTokens(false)
					.build()
				)
				.clientSettings(
					ClientSettings.builder()
					.requireAuthorizationConsent(true)
					.build()
				).build();

				RegisteredClient backendClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("backend")
				.clientSecret("backendsecret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://spring.io/auth")
				.scope("user:read")
				.scope("user:write")
				.tokenSettings(
					TokenSettings.builder()
					.accessTokenTimeToLive(Duration.ofHours(1))
					.build()
				)
				.clientSettings(
					ClientSettings.builder()
					.requireAuthorizationConsent(false)
					.build()
				).build();


		return new InMemoryRegisteredClientRepository(
			List.of(defaultClient, backendClient)
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

}
