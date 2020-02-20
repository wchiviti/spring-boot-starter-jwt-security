package io.github.hobbstech.commons.springjwtsecurity.service;

import lombok.Data;

@Data
public class AuthenticationRequest {

    private String username;

    private String password;

}
