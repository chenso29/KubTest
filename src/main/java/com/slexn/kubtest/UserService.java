package com.slexn.multiboard.services.inter;

import com.slexn.multiboard.entities.documents.User;
import com.slexn.multiboard.entities.dtos.LoginDTO;
import com.slexn.multiboard.entities.dtos.SignUpDTO;
import com.slexn.multiboard.entities.dtos.TokenDTO;
import org.springframework.http.ResponseEntity;

public interface UserService {
    ResponseEntity<?> signUp(SignUpDTO signUpDTO);

    ResponseEntity<?> login(LoginDTO loginDTO);

    ResponseEntity<?> logout(TokenDTO tokenDTO);

    ResponseEntity<?> logoutAll(TokenDTO tokenDTO);

    ResponseEntity<?> getAccessToken(TokenDTO tokenDTO);

    ResponseEntity<?> getRefreshToken(TokenDTO tokenDTO);

    User updateUser(String name, String newName, String password, String authorization);

    Boolean getStatus(String id);

    User changeUserStatus(String id);

    Boolean validateUserRole(String id);

    User changeUserRole(String id, String role);

    User updatePassword(String id, String password);

    User findByEmail(String email);

    User findById(String id);

    User findByUsername(String name);
}
