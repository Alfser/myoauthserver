package com.example.myoauthserver.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import com.example.myoauthserver.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

	private final UserRepository userRepository;

	public OidcUserInfo loadUser(String username) {
		var currentUser = this.userRepository.findByEmail(username).orElseThrow();
		return OidcUserInfo.builder()
			.name(currentUser.getName())
			.subject(username)
			.email(currentUser.getEmail())
			.emailVerified(true)
			.build();
	}
}
