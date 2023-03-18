package com.example.myoauthserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.myoauthserver.model.UserModel;

public interface UserRepository extends JpaRepository<UserModel, Long> {

	Optional<UserModel> findByEmail(String username);
}
