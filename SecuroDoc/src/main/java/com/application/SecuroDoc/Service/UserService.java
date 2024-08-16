package com.application.SecuroDoc.Service;

import com.application.SecuroDoc.DTO.User;
import com.application.SecuroDoc.Entity.CredentialEntity;
import com.application.SecuroDoc.Entity.RoleEntity;
import com.application.SecuroDoc.Enum.LoginType;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserService {
    void createUser(String firstName, String lastName, String email, String password);
    RoleEntity getRoleName(String name);
    void verifyAccountKey(String key);
    void updateLoginAttempt(String email, LoginType loginType);
    User getUserByUserId(String userId);
    User getUserByEmail(String email);
    CredentialEntity getUserCredentialById(Long id);
    User setUpMfa(Long id);
    User cancelMfa(Long id);
    User verifyQrCode(String userId, String qrCode);
    void resetPassword(String email);
    User verifyPasswordKey(String key);
    void updatePassword(String userId, String newPassword, String confirmNewPassword);
    void updatePassword(String userId, String currentPassword, String newPassword, String confirmNewPassword);
    User updateUser(String userId, String firstName, String lastName, String email, String phone, String bio);
    void updateRole(String userId, String role);
    void toggleAccountExpired(String userId);
    void toggleAccountLocked(String userId);
    void toggleAccountEnabled(String userId);
    void toggleCredentialsExpired(String userId);
    List<User> getUsers();
    String uploadPhoto(String userId, MultipartFile file);
    User getUserById(Long id);
}
