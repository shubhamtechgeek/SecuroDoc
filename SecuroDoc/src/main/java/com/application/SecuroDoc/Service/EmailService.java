package com.application.SecuroDoc.Service;

public interface EmailService {

    void sendNewAccountEmail(String name, String to, String token) throws Exception;

    void sendPasswordResetEmail(String name, String to, String token);


}
