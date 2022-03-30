package hanu.example.springjwtcookie.service;

import hanu.example.springjwtcookie.domain.Role;
import hanu.example.springjwtcookie.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
