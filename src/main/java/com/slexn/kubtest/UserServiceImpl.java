package com.slexn.multiboard.services.impl;

import com.slexn.multiboard.entities.documents.RefreshToken;
import com.slexn.multiboard.entities.documents.Role;
import com.slexn.multiboard.entities.documents.User;
import com.slexn.multiboard.entities.dtos.LoginDTO;
import com.slexn.multiboard.entities.dtos.SignUpDTO;
import com.slexn.multiboard.entities.dtos.TokenDTO;
import com.slexn.multiboard.jwt.JwtHelper;
import com.slexn.multiboard.repository.RefreshTokenRepository;
import com.slexn.multiboard.repository.RoleRepository;
import com.slexn.multiboard.repository.UserRepository;
import com.slexn.multiboard.services.inter.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;

@Service
@Transactional
public class UserServiceImpl implements UserService {
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtHelper jwtHelper;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final RoleRepository roleRepository;

    @Autowired
    public UserServiceImpl(AuthenticationManager authenticationManager,
                           RefreshTokenRepository refreshTokenRepository,
                           UserRepository userRepository, JwtHelper jwtHelper,
                           PasswordEncoder passwordEncoder, UserDetailsServiceImpl userDetailsServiceImpl,
                           RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtHelper = jwtHelper;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsServiceImpl = userDetailsServiceImpl;
        this.roleRepository = roleRepository;
    }

    @Override
    public ResponseEntity<?> signUp(SignUpDTO signUpDTO) {
        if (userRepository.existsByUsername(signUpDTO.getUsername())) {
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpDTO.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }
        if (roleRepository.findAll().size() == 0) {
            roleRepository.insert(new Role("admin"));
            roleRepository.insert(new Role("user"));
        }

        User user = new User(signUpDTO.getUsername(), signUpDTO.getEmail(), passwordEncoder.encode(signUpDTO.getPassword()));
        if (userRepository.findAll().size() == 0) {
            user.addRole(roleRepository.findByName("admin").orElse(null));
        } else {
            user.addRole(roleRepository.findByName(signUpDTO.getRole()).orElse(null));
        }
        user.setStatus(true);
        userRepository.insert(user);
        return getResponseEntity(user);
    }

    @Override
    public ResponseEntity<?> login(LoginDTO loginDTO) {
        if (!userRepository.findByUsername(loginDTO.getUsername()).orElseThrow().getStatus()) {
            throw new RuntimeException("User deactivated");
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = (User) authentication.getPrincipal();

        return getResponseEntity(user);
    }

    @Override
    public ResponseEntity<?> logout(TokenDTO tokenDTO) {
        String refreshTokenString = tokenDTO.getRefreshToken();
        if (!userRepository.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString)).orElseThrow().getStatus()) {
            throw new RuntimeException("User deactivated");
        }
        if (jwtHelper.validateRefreshToken(refreshTokenString)
                && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString));
            return ResponseEntity.ok().build();
        }
        throw new BadCredentialsException("Invalid token");
    }

    @Override
    public ResponseEntity<?> logoutAll(TokenDTO tokenDTO) {
        String refreshTokenString = tokenDTO.getRefreshToken();
        if (!userRepository.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString)).orElseThrow().getStatus()) {
            throw new RuntimeException("User deactivated");
        }
        if (jwtHelper.validateRefreshToken(refreshTokenString)
                && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteAllByOwnerId(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            return ResponseEntity.ok().build();
        }

        throw new BadCredentialsException("Invalid token");
    }

    @Override
    public ResponseEntity<?> getAccessToken(TokenDTO tokenDTO) {
        String refreshTokenString = tokenDTO.getRefreshToken();
        if (!userRepository.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString)).orElseThrow().getStatus()) {
            throw new RuntimeException("User deactivated");
        }
        if (jwtHelper.validateRefreshToken(refreshTokenString)
                && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            User user = userDetailsServiceImpl.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            String refreshTokenId = jwtHelper.getTokenIdFromRefreshToken(refreshTokenString);
            refreshTokenRepository.deleteById(refreshTokenId);
            String accessToken = jwtHelper.generateAccessToken(user);
            String newRefreshTokenString = jwtHelper.generateRefreshToken(user, refreshTokenId);
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setId(refreshTokenId);
            refreshToken.setOwner(user);
            refreshTokenRepository.save(refreshToken);
            return ResponseEntity.ok(new TokenDTO(user.getId(), accessToken, newRefreshTokenString));
        }

        throw new BadCredentialsException("Invalid token");
    }

    @Override
    public ResponseEntity<?> getRefreshToken(TokenDTO tokenDTO) {
        String refreshTokenString = tokenDTO.getRefreshToken();
        if (!userRepository.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString)).orElseThrow().getStatus()) {
            throw new RuntimeException("User deactivated");
        }
        if (jwtHelper.validateRefreshToken(refreshTokenString)
                && refreshTokenRepository.existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {

            refreshTokenRepository.deleteById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString));
            User user = userDetailsServiceImpl.findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            return getResponseEntity(user);
        }

        throw new BadCredentialsException("Invalid token");
    }

    @Override
    public User updateUser(String name, String newName, String password, String authorization) {
        User user = userRepository.findByUsername(name).orElseThrow();
        if (!user.getStatus()) {
            throw new RuntimeException("User deactivated");
        }
        if (!user.getId().equals(authorization)) {
            throw new BadCredentialsException("You have no permissions to update this user");
        }
        if (userRepository.existsByUsername(newName)) {
            throw new IllegalArgumentException();
        }

        if (!newName.equals("")) {
            user.setUsername(newName);
        }
        if (!password.equals("")) {
            user.setPassword(passwordEncoder.encode(password));
        }
        userRepository.save(user);
        return user;
    }

    @Override
    public Boolean getStatus(String accessToken) {
        return userRepository.findById(jwtHelper.getUserIdFromAccessToken(accessToken)).orElseThrow().getStatus();
    }

    @Override
    public User changeUserStatus(String id) {
        User user = userRepository.findById(id).orElseThrow();
        user.setStatus(!user.getStatus());
        userRepository.save(user);
        return user;
    }

    @Override
    public Boolean validateUserRole(String id) {
        return userRepository.findById(id)
                .orElseThrow()
                .getRoles()
                .stream()
                .map(Role::getName)
                .filter(e -> e.equals("admin"))
                .toList()
                .size() != 0;
    }

    @Override
    public User changeUserRole(String id, String role) {
        User user = userRepository.findById(id).orElseThrow();
        user.setRoles(new HashSet<>());
        user.addRole(roleRepository.findByName(role).orElseThrow());
        userRepository.save(user);
        return user;
    }

    @Override
    public User updatePassword(String id, String password) {
        User user = userRepository.findById(id).orElseThrow();
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
        return user;
    }

    private ResponseEntity<?> getResponseEntity(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setOwner(user);
        refreshTokenRepository.save(refreshToken);

        String accessToken = jwtHelper.generateAccessToken(user);
        String newRefreshTokenString = jwtHelper.generateRefreshToken(user, refreshToken.getId());

        return ResponseEntity.ok(new TokenDTO(user.getId(), accessToken, newRefreshTokenString));
    }

    @Override
    public User findByEmail(String email) {
        System.out.println(email);
        return userRepository.findByEmail(email).orElseThrow();
    }

    @Override
    public User findById(String id) {
        return userRepository.findById(id).orElseThrow();
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow();
    }

}
