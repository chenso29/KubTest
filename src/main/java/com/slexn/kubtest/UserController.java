package com.slexn.multiboard.controllers;

import com.slexn.multiboard.entities.documents.User;
import com.slexn.multiboard.jwt.JwtHelper;
import com.slexn.multiboard.repository.UserRepository;
import com.slexn.multiboard.services.inter.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserRepository userRepository;
    private final HttpServletRequest request;
    private final JwtHelper jwtHelper;
    private final UserService userService;

    @Autowired
    public UserController(UserRepository userRepository, HttpServletRequest request, JwtHelper jwtHelper, UserService userService) {
        this.userRepository = userRepository;
        this.request = request;
        this.jwtHelper = jwtHelper;
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@AuthenticationPrincipal User user) {
        if (!userService.getStatus(request.getHeader("Authorization").substring(7))) {
            throw new RuntimeException("User deactivated");
        } else if (jwtHelper.validateAccessToken(request.getHeader("Authorization").substring(7))) {
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/{id}")
    @PreAuthorize("#user.id == #id")
    public ResponseEntity<?> me(@AuthenticationPrincipal User user, @PathVariable String id) {
        if (!userService.getStatus(request.getHeader("Authorization").substring(7))) {
            throw new RuntimeException("User deactivated");
        }
        return ResponseEntity.ok(userRepository.findById(id));
    }

    @GetMapping()
    public ResponseEntity<?> getUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PatchMapping("/{name}")
    public ResponseEntity<?> updateUser(@PathVariable String name, @RequestBody Map<String, String> body) {
        if (!userService.getStatus(request.getHeader("Authorization").substring(7))) {
            throw new RuntimeException("User deactivated");
        }
        return ResponseEntity.ok(userService.updateUser(name, body.get("newName"), body.get("password"), jwtHelper.getUserIdFromAccessToken(request.getHeader("Authorization").substring(7))));
    }

    @PatchMapping("/password")
    public ResponseEntity<?> updatePassword(@RequestBody Map<String, String> body) {
        return ResponseEntity.ok(userService.updatePassword(jwtHelper.getUserIdFromAccessToken(request.getHeader("Authorization").substring(7)), body.get("password")));
    }

    //Only with admin role
    @PatchMapping("/status")
    public ResponseEntity<?> changUserStatus(@RequestBody Map<String, String> body) {
        if (userService.validateUserRole(jwtHelper.getUserIdFromAccessToken(request.getHeader("Authorization").substring(7)))) {
            return ResponseEntity.ok(userService.changeUserStatus(body.get("id")));
        }
        return ResponseEntity.badRequest().build();
    }

    //Only with admin role
    @PatchMapping("/role")
    public ResponseEntity<?> changeUserRole(@RequestBody Map<String, String> body) {
        if (userService.validateUserRole(jwtHelper.getUserIdFromAccessToken(request.getHeader("Authorization").substring(7)))) {
            return ResponseEntity.ok(userService.changeUserRole(body.get("id"), body.get("role")));
        }
        return ResponseEntity.badRequest().build();
    }

}
