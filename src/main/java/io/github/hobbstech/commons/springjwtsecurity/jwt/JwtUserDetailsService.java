package io.github.hobbstech.commons.springjwtsecurity.jwt;

import io.github.hobbstech.commons.usermanager.user.dao.UserDao;
import io.github.hobbstech.commons.usermanager.accesscontrol.authorities.model.Authority;
import io.github.hobbstech.commons.usermanager.accesscontrol.groupauthorities.model.GroupAuthority;
import io.github.hobbstech.commons.usermanager.accesscontrol.groupauthorities.service.GroupAuthorityService;
import io.github.hobbstech.commons.usermanager.accesscontrol.userauthorities.model.UserAuthority;
import io.github.hobbstech.commons.usermanager.accesscontrol.userauthorities.service.UserAuthorityService;
import io.github.hobbstech.commons.usermanager.user.dao.UserDao;
import lombok.val;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("jwtUserDetailsService")
public class JwtUserDetailsService implements UserDetailsService {

    private final UserDao userDao;

    private final GroupAuthorityService groupAuthorityService;

    private final UserAuthorityService userAuthorityService;

    public JwtUserDetailsService(UserDao userDao, GroupAuthorityService groupAuthorityService,
                                 UserAuthorityService userAuthorityService) {
        this.userDao = userDao;
        this.groupAuthorityService = groupAuthorityService;
        this.userAuthorityService = userAuthorityService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        val userOptional = userDao.findByUsername(username);

        if (userOptional.isPresent()) {

            val user = userOptional.get();

            val groupAuthorities = groupAuthorityService.findByGroup(user.getGroup().getId());
            groupAuthorities.stream().map(GroupAuthority::getAuthority)
                    .map(Authority::getName)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(user::addAuthority);

            val userAuthorities = userAuthorityService.findByUser(user.getId());
            userAuthorities.stream().map(UserAuthority::getAuthority)
                    .map(Authority::getName)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(user::addAuthority);

            return user;

        }

        throw new UsernameNotFoundException("User record not found");
    }
}
