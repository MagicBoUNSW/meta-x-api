package com.bit.metax.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    ROLE_ADMIN,ROLE_FREE_MEMBER;

    public String getAuthority() {
        return name();
    }
}
