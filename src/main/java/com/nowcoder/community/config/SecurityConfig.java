package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

/**
 * Created by xieli on 2021/2/4.
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略静态资源的访问
        web.ignoring().antMatchers("/resources/**");
    }

    // AuthenticationManager: 认证的核心接口
    // AuthenticationManagerBuilder: 用于构建 AuthenticationManager 对象的工具
    // ProviderManager: AuthenticationManager 接口的默认实现类
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内置的认证规则
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));

        // 自定义认证规则
        // AuthenticationProvider: ProviderManager 持有一组 AuthenticationProvider, 每个 AuthenticationProvider 负责一种认证
        // 委托模式: ProviderManager 将认证委托给 AuthenticationProvider
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication: 用于封装认证信息的接口, 不同的实现类代表不同类型的认证信息
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();

                User user = userService.findUserByName(username);
                if (user == null) {
                    throw new UsernameNotFoundException("账号不存在！");
                }

                password = CommunityUtil.md5(password + user.getSalt());
                if (!user.getPassword().equals(password)) {
                    throw new BadCredentialsException("密码不正确");
                }

                // principal: 主要信息, credentials: 证书, authorities: 权限
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            // 当前的 AuthenticationProvider 支持哪种类型的认证
            @Override
            public boolean supports(Class<?> aClass) {
                // UsernamePasswordAuthenticationToken: Authentication 接口的常用实现类
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
            }
        });
    }
}
