/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package st.malike.auth.server.service.security;

import java.util.LinkedList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import st.malike.auth.server.model.User;
import st.malike.auth.server.service.UserService;

/**
 *
 * @author malike_st
 */
@Service
public class UserAuthConfigService {

    @Autowired
    private UserService userService;

    public User getUser(String email) {
        return userService.findByEmail(email);
    }

    public List<GrantedAuthority> getRights(User user) {
        List<GrantedAuthority> grantedAuthority = new LinkedList<>();
        List<String> right = user.getRights();
        if (null != right && !right.isEmpty()) {
            right.stream().forEach(r -> {
                grantedAuthority.add(new SimpleGrantedAuthority(r));
            });
        }
        return grantedAuthority;
    }

    public Authentication signInUser(User user, List<GrantedAuthority> roles) {
        UserDetails springSecurityUser = new org.springframework.security.core.userdetails.User(user.getEmail(), user.getId(), roles);
        Authentication authentication = new UsernamePasswordAuthenticationToken(springSecurityUser, user.getId(), roles);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

}
