package com.application.SecuroDoc.Event;

import com.application.SecuroDoc.Entity.UserEntity;
import com.application.SecuroDoc.Enum.EventType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
public class UserEvent {
    private UserEntity user;
    private EventType type;
    private Map<?, ?> data;
}
