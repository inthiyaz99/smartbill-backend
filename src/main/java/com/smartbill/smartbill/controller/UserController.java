package com.smartbill.smartbill.controller;

import com.smartbill.smartbill.model.LoginHistory;
import com.smartbill.smartbill.model.User;
import com.smartbill.smartbill.repository.LoginHistoryRepository;
import com.smartbill.smartbill.repository.UserRepository;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")

@CrossOrigin(
    origins = {
        "https://smartbill-frontend-hazel.vercel.app",
        "https://smartbill-frontend-myjnv4whz-inthiyaz99.vercel.app"
    },
    allowedHeaders = "*",
    methods = {
        RequestMethod.GET,
        RequestMethod.POST,
        RequestMethod.PUT,
        RequestMethod.DELETE,
        RequestMethod.PATCH,
        RequestMethod.OPTIONS
    }
)
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

        if (user.getFullName() == null
                || user.getFullName().isBlank()
                || user.getEmail() == null
                || user.getEmail().isBlank()
                || user.getMobile() == null
                || user.getMobile().isBlank()
                || user.getPassword() == null
                || user.getPassword().isBlank()) {
            return ResponseEntity.badRequest()
                    .body("Name, email, mobile and password are required");
        }

        String name = user.getFullName().trim();
        String email = user.getEmail().trim().toLowerCase();
        String mobile = user.getMobile().trim();

        if (user.getPassword().length() < 8) {
            return ResponseEntity.badRequest()
                    .body("Password must contain at least 8 characters");
        }

        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest()
                    .body("Email already registered");
        }

        if (userRepository.findByMobile(mobile).isPresent()) {
            return ResponseEntity.badRequest()
                    .body("Mobile number already registered");
        }

        user.setFullName(name);
        user.setEmail(email);
        user.setMobile(mobile);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    // LOGIN USING EMAIL OR MOBILE
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginUser) {

        Optional<User> user;
        String loginMethod;

        if (loginUser.getEmail() != null
                && !loginUser.getEmail().isBlank()) {

            user = userRepository.findByEmail(
                    loginUser.getEmail().trim().toLowerCase());
            loginMethod = "EMAIL";

        } else if (loginUser.getMobile() != null
                && !loginUser.getMobile().isBlank()) {

            user = userRepository.findByMobile(
                    loginUser.getMobile().trim());
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

        User loggedInUser = user.get();

        LoginHistory history = new LoginHistory();
        history.setUserId(loggedInUser.getId());
        history.setLoginTime(LocalDateTime.now());
        history.setLoginMethod(loginMethod);
        loginHistoryRepository.save(history);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", loggedInUser.getId());
        response.put("fullName", loggedInUser.getFullName());
        response.put("email", loggedInUser.getEmail());
        response.put("mobile", loggedInUser.getMobile());

        return ResponseEntity.ok(response);
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
    public ResponseEntity<?> getLoginHistory(
            @PathVariable Long userId) {

        return ResponseEntity.ok(
                loginHistoryRepository
                        .findByUserIdOrderByLoginTimeDesc(userId));
    }

    // FIND USER BY EMAIL
    @GetMapping("/by-email")
    public ResponseEntity<?> getUserByEmail(
            @RequestParam String email) {

        Optional<User> user = userRepository.findByEmail(
                email.trim().toLowerCase());

        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        return ResponseEntity.ok(toSafeUserResponse(user.get()));
    }

    // FIND USER BY MOBILE
    @GetMapping("/by-mobile")
    public ResponseEntity<?> getUserByMobile(
            @RequestParam String mobile) {

        Optional<User> user = userRepository.findByMobile(mobile.trim());

        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        return ResponseEntity.ok(toSafeUserResponse(user.get()));
    }

    // NEVER RETURN THE PASSWORD HASH
    private Map<String, Object> toSafeUserResponse(User user) {

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", user.getId());
        response.put("fullName", user.getFullName());
        response.put("email", user.getEmail());
        response.put("mobile", user.getMobile());

        return response;
    }
}
