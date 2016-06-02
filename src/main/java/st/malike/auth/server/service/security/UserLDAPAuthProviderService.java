/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package st.malike.auth.server.service.security;

import java.util.List;
import javax.naming.directory.SearchControls;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Role;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import st.malike.auth.server.model.User;
import st.malike.auth.server.service.UserService;
import st.malike.auth.server.util.LDAPMapperUtil;

/**
 *
 * @author malike_st
 */
@Component
public class UserLDAPAuthProviderService implements AuthenticationProvider {

    @Autowired
    private LdapTemplate ldapTemplate;
    @Autowired
    private UserService userService;
    @Value("${auth.ldap.context.field.email}")
    private String emailField;
    @Autowired
    private LDAPMapperUtil lDAPMapperUtil;
    @Autowired
    private UserAuthConfigService authConfigService;
    @Value("${auth.ldap.contextSource.search.scope}")
    private String searchScope;  //defines the search scope of LDAP server

    @Override
    public Authentication authenticate(Authentication a) throws AuthenticationException {
        String name = a.getName();
        String password = a.getCredentials().toString();
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter(emailField, name));
        boolean auth = ldapTemplate.authenticate(LdapUtils.emptyLdapName(), filter.toString(), password);

        User user = userService.findByEmail(name);
        if (auth) {
            //if this is the first time user logs in, we can create an account for user in mongodb
            // although user records exist in LDAP, we need a user created in our database as well ..for obvious reasons
            if (null == user) {

                SearchControls searchcontrols = new SearchControls();
                if (searchScope.equalsIgnoreCase("subtree")) {
                    searchcontrols.setSearchScope(SearchControls.SUBTREE_SCOPE);
                } else {
                    searchcontrols.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                }

                //find user by email address
                List users = ldapTemplate.search(LdapUtils.emptyLdapName(), filter.toString(), searchcontrols, lDAPMapperUtil);
                if (!users.isEmpty()) {
                    user = (User) users.get(0);
                    //add default rights to user
                    userService.save(user);
                }
            }
            List<GrantedAuthority> roleAuthority = authConfigService.getRights(user); //
            return authConfigService.signInUser(user, roleAuthority);
        }

        throw new AuthenticationException("You don't have access to the application although your LDAP authentication maybe correct") {
        };
    }

    @Override
    public boolean supports(Class<?> type) {
        return type.equals(UsernamePasswordAuthenticationToken.class);
    }

}
