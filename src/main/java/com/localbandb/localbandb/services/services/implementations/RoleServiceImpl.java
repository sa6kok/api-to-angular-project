package com.localbandb.localbandb.services.services.implementations;

import com.localbandb.localbandb.data.models.Role;
import com.localbandb.localbandb.data.repositories.RoleRepository;
import com.localbandb.localbandb.services.services.RoleService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class RoleServiceImpl implements RoleService {
  private final RoleRepository roleRepository;

  public RoleServiceImpl(RoleRepository roleRepository) {
    this.roleRepository = roleRepository;
  }

  @Override
  @PreAuthorize("permitAll")
  public Role findByAuthority(String authority) {
    return roleRepository.findByAuthority(authority);
  }


  @Override
  @PreAuthorize("permitAll")
  public Set<Role> findAll() {
    return new HashSet<>(roleRepository.findAll());
  }
}
