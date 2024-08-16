package com.application.SecuroDoc.Validation;

import com.application.SecuroDoc.Entity.UserEntity;
import com.application.SecuroDoc.Exception.ApiException;

public class UserValidation {

    public static void verifyAccountStatus(UserEntity userEntity){
        if(!userEntity.isEnabled()) throw new ApiException("Account is disabled.");
        if(!userEntity.isAccountNonExpired()) throw new ApiException("Account is expired.");
        if(!userEntity.isAccountNonLocked()) throw new ApiException("Account is Locked.");
    }

}
