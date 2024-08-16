package com.application.SecuroDoc.Resource;

import com.application.SecuroDoc.DTO.*;
import com.application.SecuroDoc.Domain.Response;
import com.application.SecuroDoc.Handler.SecuroLogoutHandler;
import com.application.SecuroDoc.Service.JwtService;
import com.application.SecuroDoc.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static com.application.SecuroDoc.Constant.Constants.FILE_STORAGE;
import static com.application.SecuroDoc.Enum.TokenType.ACCESS;
import static com.application.SecuroDoc.Enum.TokenType.REFRESH;
import static com.application.SecuroDoc.Utils.RequestUtils.getResponse;
import static java.util.Collections.emptyMap;
import static java.util.Map.of;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;
import static org.springframework.http.MediaType.IMAGE_PNG_VALUE;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import static java.net.URI.create;


@RestController
@RequiredArgsConstructor
@RequestMapping(path = { "/user" })
public class UserResource {
    private final UserService userService;
    private final JwtService jwtService;
    private final SecuroLogoutHandler logoutHandler;

    @PostMapping("/register")
    public ResponseEntity<Response> saveUser(@RequestBody @Valid UserRequest user, HttpServletRequest request) {
        userService.createUser(user.getFirstName(), user.getLastName(), user.getEmail(), user.getPassword());
        return ResponseEntity.created(create("")).body(getResponse(request, emptyMap(), "Account created. Check your email to enable your account.", CREATED));
    }

    @GetMapping("/verify/account")
    public ResponseEntity<Response> verifyAccount(@RequestParam("key") String key, HttpServletRequest request) throws InterruptedException {
        userService.verifyAccountKey(key);
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Account verified.", OK));
    }

    @GetMapping("/profile")
    @PreAuthorize("hasAnyAuthority('user:read') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> profile(@AuthenticationPrincipal User userPrincipal, HttpServletRequest request) {
        var user = userService.getUserByUserId(userPrincipal.getUserId());
        return ResponseEntity.ok().body(getResponse(request, of("user", user), "Profile retrieved", OK));
    }

    @PatchMapping("/update")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> update(@AuthenticationPrincipal User userPrincipal, @RequestBody UserRequest userRequest, HttpServletRequest request) {
        var user = userService.updateUser(userPrincipal.getUserId(), userRequest.getFirstName(), userRequest.getLastName(), userRequest.getEmail(), userRequest.getPhone(), userRequest.getBio());
        return ResponseEntity.ok().body(getResponse(request, of("user", user), "User updated successfully", OK));
    }

    @PatchMapping("/updaterole")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> updateRole(@AuthenticationPrincipal User userPrincipal, @RequestBody RoleRequest roleRequest, HttpServletRequest request) {
        userService.updateRole(userPrincipal.getUserId(), roleRequest.getRole());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Role updated successfully", OK));
    }

    @PatchMapping("/toggleaccountexpired")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> toggleAccountExpired(@AuthenticationPrincipal User user, HttpServletRequest request) {
        userService.toggleAccountExpired(user.getUserId());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Account updated successfully", OK));
    }

    @PatchMapping("/toggleaccountlocked")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> toggleAccountLocked(@AuthenticationPrincipal User user, HttpServletRequest request) {
        userService.toggleAccountLocked(user.getUserId());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Account updated successfully", OK));
    }

    @PatchMapping("/toggleaccountenabled")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> toggleAccountEnabled(@AuthenticationPrincipal User user, HttpServletRequest request) {
        userService.toggleAccountEnabled(user.getUserId());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Account updated successfully", OK));
    }

    @PatchMapping("/togglecredentialsexpired")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> toggleCredentialsExpired(@AuthenticationPrincipal User user, HttpServletRequest request) {
        userService.toggleCredentialsExpired(user.getUserId());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Account updated successfully", OK));
    }

    @PatchMapping("/mfa/setup")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> setUpMfa(@AuthenticationPrincipal User userPrincipal, HttpServletRequest request) {
        var user = userService.setUpMfa(userPrincipal.getId());
        return ResponseEntity.ok().body(getResponse(request, of("user", user), "MFA set up successfully", OK));
    }

    @PatchMapping("/mfa/cancel")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> cancelMfa(@AuthenticationPrincipal User userPrincipal, HttpServletRequest request) {
        var user = userService.cancelMfa(userPrincipal.getId());
        return ResponseEntity.ok().body(getResponse(request, of("user", user), "MFA canceled successfully", OK));
    }

    @PostMapping("/verify/qrcode")
    public ResponseEntity<Response> verifyQrcode(@RequestBody QrCodeRequest qrCodeRequest, HttpServletRequest request, HttpServletResponse response) {
        var user = userService.verifyQrCode(qrCodeRequest.getUserId(), qrCodeRequest.getQrCode());
        jwtService.addCookie(response, user, ACCESS);
        jwtService.addCookie(response, user, REFRESH);
        return ResponseEntity.ok().body(getResponse(request, of("user", user), "QR code verified", OK));
    }

    // START - Reset password when user is logged in
    @PatchMapping("/updatepassword")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> updatePassword(@AuthenticationPrincipal User user, @RequestBody UpdatePasswordRequest passwordRequest, HttpServletRequest request) {
        userService.updatePassword(user.getUserId(), passwordRequest.getPassword(), passwordRequest.getNewPassword(), passwordRequest.getConfirmNewPassword());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Password updated successfully", OK));
    }
    // END - Reset password when user is logged in

    // START - Reset password when user is NOT logged in
    @PostMapping("/resetpassword")
    public ResponseEntity<Response> resetPassword(@RequestBody @Valid EmailRequest emailRequest, HttpServletRequest request) {
        userService.resetPassword(emailRequest.getEmail());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "We sent you an email to reset your password", OK));
    }


    @GetMapping("/verify/password")
    public ResponseEntity<Response> verifyPassword(@RequestParam("key") String key, HttpServletRequest request) {
        var user = userService.verifyPasswordKey(key);
        return ResponseEntity.ok().body(getResponse(request, of("user", user), "Enter new password", OK));
    }

    @PostMapping("/resetpassword/reset")
    public ResponseEntity<Response> doResetPassword(@RequestBody @Valid ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        userService.updatePassword(resetPasswordRequest.getUserId(), resetPasswordRequest.getNewPassword(), resetPasswordRequest.getConfirmNewPassword());
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Password reset successfully", OK));
    }
    // END - Reset password when user is NOT logged in

    @GetMapping(path = "/list")
    @PreAuthorize("hasAnyAuthority('user:read') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> getUsers(@AuthenticationPrincipal User user, HttpServletRequest request) {
        return ResponseEntity.ok().body(getResponse(request, of("users", userService.getUsers()), "Users retrieved", OK));
    }

    @PatchMapping("/photo")
    @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Response> uploadPhoto(@AuthenticationPrincipal User user, @RequestParam("file") MultipartFile file, HttpServletRequest request) {
        var imageUrl = userService.uploadPhoto(user.getUserId(), file);
        return ResponseEntity.ok().body(getResponse(request, of("imageUrl", imageUrl), "Photo updated successfully", OK));
    }

    @GetMapping(path = "/image/{filename}", produces = { IMAGE_PNG_VALUE, IMAGE_JPEG_VALUE })
    public byte[] getPhoto(@PathVariable("filename") String filename) throws IOException {
        return Files.readAllBytes(Paths.get(FILE_STORAGE + filename));
    }

    @PostMapping("/logout")
    public ResponseEntity<Response> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        logoutHandler.logout(request, response, authentication);
        return ResponseEntity.ok().body(getResponse(request, emptyMap(), "You've logged out successfully", OK));
    }
}
