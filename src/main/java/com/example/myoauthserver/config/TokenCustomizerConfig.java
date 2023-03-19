package com.example.myoauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.example.myoauthserver.service.OidcUserInfoService;

@Configuration
public class TokenCustomizerConfig {

	@Bean 
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
			OidcUserInfoService userInfoService) {
		return (context) -> {
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				OidcUserInfo userInfo = userInfoService.loadUser( 
						context.getPrincipal().getName());
				context.getClaims().claims(claims ->
						claims.putAll(userInfo.getClaims()));
			}

			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					claims.put("authorities", context.getPrincipal().getAuthorities());
				});
			}
		};
	}

}