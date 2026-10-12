package com.smartbill.smartbill.controller;

import com.smartbill.smartbill.model.LoginHistory;
import com.smartbill.smartbill.model.User;
import com.smartbill.smartbill.repository.LoginHistoryRepository;
import com.smartbill.smartbill.repository.UserRepository;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = {
    "https://smartbill-frontend-hazel.vercel.app",
    "https://smartbill-frontend-myjnv4whz-inthiyaz99.vercel.app"
})
public class UserController {

    private final UserRepository userRepository;
    private final LoginHistoryRepository loginHistoryRepository;

    private final BCryptPasswordEncoder passwordEncoder =
            new BCryptPasswordEncoder();

    public UserController(
            UserRepository userRepository,
            LoginHistoryRepository loginHistoryRepository) {
        this.userRepository = userRepository;
        this.loginHistoryRepository = loginHistoryRepository;
    }

    // REGISTER
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {

        if (user.getEmail() == null || user.getEmail().isBlank()
                || user.getPassword() == null || user.getPassword().isBlank()
                || user.getMobile() == null || user.getMobile().isBlank()) {
            return ResponseEntity.badRequest()
                    .body("Name, email, mobile and password are required");
        }

        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity.badRequest()
                    .body("Email already registered");
        }

        if (userRepository.findByMobile(user.getMobile()).isPresent()) {
            return ResponseEntity.badRequest()
                    .body("Mobile number already registered");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginUser) {

        Optional<User> user;
        String loginMethod;

        if (loginUser.getEmail() != null
                && !loginUser.getEmail().isBlank()) {
            user = userRepository.findByEmail(loginUser.getEmail());
            loginMethod = "EMAIL";
        } else if (loginUser.getMobile() != null
                && !loginUser.getMobile().isBlank()) {
            user = userRepository.findByMobile(loginUser.getMobile());
            loginMethod = "MOBILE";
        } else {
            return ResponseEntity.badRequest()
                    .body("Email or mobile number is required");
        }

        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        if (loginUser.getPassword() == null
                || !passwordEncoder.matches(
                        loginUser.getPassword(),
                        user.get().getPassword())) {
            return ResponseEntity.badRequest().body("Invalid password");
        }

        LoginHistory history = new LoginHistory();
        history.setUserId(user.get().getId());
        history.setLoginTime(LocalDateTime.now());
        history.setLoginMethod(loginMethod);
        loginHistoryRepository.save(history);

        return ResponseEntity.ok(user.get());
    }

    // LOGOUT
    @PostMapping("/logout/{userId}")
    public ResponseEntity<?> logout(@PathVariable Long userId) {

        Optional<LoginHistory> history =
                loginHistoryRepository.findAll().stream()
                        .filter(h -> h.getUserId() != null
                                && h.getUserId().equals(userId)
                                && h.getLogoutTime() == null)
                        .reduce((first, second) -> second);

        if (history.isPresent()) {
            LoginHistory loginHistory = history.get();
            loginHistory.setLogoutTime(LocalDateTime.now());
            loginHistoryRepository.save(loginHistory);
        }

        return ResponseEntity.ok("Logout recorded");
    }

    // LOGIN HISTORY
    @GetMapping("/login-history/{userId}")
    public ResponseEntity<?> getLoginHistory(@PathVariable Long userId) {
        return ResponseEntity.ok(
                loginHistoryRepository
                        .findByUserIdOrderByLoginTimeDesc(userId));
    }

    // FIND USER BY EMAIL
    @GetMapping("/by-email")
    public ResponseEntity<?> getUserByEmail(
            @RequestParam String email) {

        Optional<User> user = userRepository.findByEmail(email);

        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        return ResponseEntity.ok(user.get());
    }

    // FIND USER BY MOBILE
    @GetMapping("/by-mobile")
    public ResponseEntity<?> getUserByMobile(
            @RequestParam String mobile) {

        Optional<User> user = userRepository.findByMobile(mobile);

        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        return ResponseEntity.ok(user.get());
    }
}
