package com.example.myoauthserver.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity(name = "auth_user")
public class UserModel {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String name;
	
    @Column(unique = true)
	private String email;
	
    private String password;
	
    @Enumerated(EnumType.STRING)
	private Type type = Type.ADMIN;
    

	public enum Type {
		ADMIN, CLIENT;
	}
}
