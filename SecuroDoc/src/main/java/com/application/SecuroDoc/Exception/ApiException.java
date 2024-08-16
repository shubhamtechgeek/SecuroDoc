package com.application.SecuroDoc.Exception;

public class ApiException extends RuntimeException{
    public ApiException (String message) { super(message); }
    public ApiException() { super("An error occurred"); }
}
