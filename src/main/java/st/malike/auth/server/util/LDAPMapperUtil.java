/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package st.malike.auth.server.util;

import org.springframework.ldap.NamingException;
import javax.naming.directory.Attributes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.stereotype.Component;
import st.malike.auth.server.model.User;

/**
 *
 * @author malike_st
 */
@Component(value = "coreLDAPMapper")
public class LDAPMapperUtil implements AttributesMapper {

    @Value("${auth.ldap.context.field.email}")
    private String emailField;

    @Override
    public User mapFromAttributes(Attributes attributes) throws NamingException {
        try {
            User user = new User();
            String email = null;
            if (attributes.get(emailField) != null) {
                email = (String) attributes.get(emailField).get();
            }
            if (null == email) {
                throw new NamingException("User doesn't have an email") {
                };
            }
            user.setEmail(email.toLowerCase());
            return user;

        } catch (javax.naming.NamingException e) {
            throw new NamingException("User doesn't have an email") {
            };
        }
    }

}
