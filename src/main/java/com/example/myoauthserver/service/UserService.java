package com.example.myoauthserver.service;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.myoauthserver.model.UserModel;
import com.example.myoauthserver.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        final var user = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException(email));

        final var simpleGrantedAuthority = new SimpleGrantedAuthority(user.getType().name());

        return new User(
                user.getEmail(),
                user.getPassword(),
                List.of(simpleGrantedAuthority)
        );
    }

    public UserModel create(UserModel user){
        return userRepository.save(user);
    }

}
