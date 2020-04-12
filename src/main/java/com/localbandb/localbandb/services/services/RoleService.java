package com.localbandb.localbandb.services.services;

import com.localbandb.localbandb.data.models.Role;

import java.util.Set;

public interface RoleService {

  Role findByAuthority(String authority);

  Set<Role> findAll();
}
