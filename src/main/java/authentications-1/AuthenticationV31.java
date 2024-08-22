 ```java
// code-start

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

@SpringBootApplication
public class LoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/login")
class LoginController {

    @PostMapping
    public ResponseEntity<String> login(@RequestBody LoginDto loginDto) {
        try {
            // Security: Validate user input to prevent injection attacks
            if (validateLoginDto(loginDto)) {
                // Security: Check if user exists and password is valid
                UserDetails user = userService.findByUsername(loginDto.getUsername());
                if (user != null && user.getPassword().equals(loginDto.getPassword())) {
                    // Security: Multi-Factor Authentication (MFA)
                    if (userService.verifyMfaToken(loginDto.getMfaToken())) {
                        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        return ResponseEntity.ok("User logged in successfully");
                    } else {
                        throw new AuthenticationException("Invalid MFA token");
                    }
                } else {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
                }
            } else {
                return ResponseEntity.badRequest().body("Invalid input data");
            }
        } catch (AuthenticationException e) {
            // Error handling: Log and return appropriate response
            log.error("Authentication error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication error: " + e.getMessage());
        }
    }

    private boolean validateLoginDto(LoginDto loginDto) {
        // Validate loginDto fields
        return loginDto.getUsername() != null && loginDto.getPassword() != null && loginDto.getMfaToken() != null;
    }
}

class LoginDto {
    private String username;
    private String password;
    private String mfaToken;

    // Getters and setters
}

interface IUserService {
    UserDetails findByUsername(String username);
    boolean verifyMfaToken(String mfaToken);
}

class UserService implements IUserService {
    // Implement user service logic
}

// code-end
```