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
	private final Map<String, Object> userInfo = new HashMap<>();

	public OidcUserInfo loadUser(String username) {
		userInfo.put(username, this.userRepository.findByEmail(username).orElseThrow());
		return new OidcUserInfo(userInfo);
	}
}
