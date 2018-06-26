package com.us.example.config;

import com.us.example.service.CustomUserService;
import com.us.example.service.MyFilterSecurityInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * Created by yangyibo on 17/1/18.
 * 配置的总控 
 *  1.  AuthenticationManagerBuilder--->>CustomUserService  
 *      这两个配合返回用户信息 其中CustomUserService可以自定义只要实现UserDetailsService接口 
 *      返回userdetail就可以了 包括用户的基础信息  以及权限信息
 *  2.  configure(HttpSecurity http)
 *      HttpSecurity 这个应该对于所有的请求的配置 springboot按照这个配置 处理所有的请求
 *      这个方法 配置要处理的url 
 *  3.  MyFilterSecurityInterceptor 自定义的filter 真正工作的类
 *         MyAccessDecisionManager（AccessDecisionManager接口）这个类用来判断是否拥有权限访问
 *         FilterInvocationSecurityMetadataSource 自定义实现这个接口 返回这个请求的是否在权限类表中 如果有返回
 */


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyFilterSecurityInterceptor myFilterSecurityInterceptor;


    @Bean
    UserDetailsService customUserService() { //注册UserDetailsService 的bean
        return new CustomUserService();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserService()); //user Details Service验证

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated() //任何请求,登录后可以访问
                .and()
                .formLogin()
                .loginPage("/login")
                .failureUrl("/login?error")
                .permitAll() //登录页面用户任意访问
                .and()
                .logout().permitAll(); //注销行为任意访问
        http.addFilterBefore(myFilterSecurityInterceptor, FilterSecurityInterceptor.class)
                .csrf().disable();


    }
}

