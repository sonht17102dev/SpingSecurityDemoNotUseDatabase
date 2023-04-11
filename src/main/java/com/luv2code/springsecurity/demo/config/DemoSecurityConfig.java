package com.luv2code.springsecurity.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		// add our users for in memory authentication
		
		UserBuilder users = User.withDefaultPasswordEncoder();
		
		auth.inMemoryAuthentication()
			.withUser(users.username("john").password("test123").roles("EMPLOYEE"))
			.withUser(users.username("mary").password("test123").roles("EMPLOYEE", "MANAGER"))
			.withUser(users.username("susan").password("test123").roles("EMPLOYEE", "ADMIN"));
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers("/employees").hasRole("EMPLOYEE")
			.antMatchers("/leaders/**").hasRole("MANAGER")
			.antMatchers("/systems/**").hasRole("ADMIN")
			.and()
			.formLogin()
				.loginPage("/showMyLoginPage")
				.loginProcessingUrl("/authenticateTheUser")
				.permitAll()
			.and()
			.logout()
				.logoutSuccessUrl("/")  // after logout redirect to landing page (root)
				.permitAll()
			.and()
			.exceptionHandling().accessDeniedPage("/access-denied");
		
	}
		
}

/*
 * Phương thức configure(HttpSecurity http) được sử dụng trong cấu hình Spring Security để xác thực và phân quyền truy cập trên ứng dụng web. Dưới đây là giải thích từng dòng code trong phương thức này:

http.authorizeRequests(): Khai báo cho phép xác thực các request đến server.
.antMatchers("/"): Cấu hình cho phép tất cả các người dùng có thể truy cập trang chủ.
.antMatchers("/employees").hasRole("EMPLOYEE"): 
Cấu hình cho phép chỉ người dùng có quyền "EMPLOYEE" mới được phép truy cập vào trang "/employees".
.antMatchers("/leaders/**").hasRole("MANAGER"): 
Cấu hình cho phép chỉ người dùng có quyền "MANAGER" mới được phép truy cập vào tất cả các URL 
bắt đầu bằng "/leaders".
.antMatchers("/systems/**").hasRole("ADMIN"): 
Cấu hình cho phép chỉ người dùng có quyền "ADMIN" mới được phép truy cập vào tất cả các URL 
bắt đầu bằng "/systems".
.formLogin(): Cấu hình cho phép đăng nhập bằng form.
.loginPage("/showMyLoginPage"): Cấu hình cho phép điều hướng đến trang đăng nhập do người dùng tạo ra.
.loginProcessingUrl("/authenticateTheUser"): Cấu hình URL để xử lý đăng nhập.
.permitAll(): Cho phép tất cả người dùng đều có thể truy cập vào trang đăng nhập và xử lý đăng nhập.
.logout(): Cấu hình cho phép đăng xuất.
.logoutSuccessUrl("/"): Cấu hình cho phép sau khi đăng xuất thành công, chuyển hướng đến trang chủ.
.permitAll(): Cho phép tất cả người dùng đều có thể đăng xuất.
 
 
 <?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:security="http://www.springframework.org/schema/security"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd">

    <!-- Configure authentication -->
    <security:authentication-manager>
        <security:authentication-provider>
            <security:user-service>
                <security:user name="john" password="test123" authorities="ROLE_EMPLOYEE"/>
                <security:user name="mary" password="test123" authorities="ROLE_EMPLOYEE, ROLE_MANAGER"/>
                <security:user name="susan" password="test123" authorities="ROLE_EMPLOYEE, ROLE_ADMIN"/>
            </security:user-service>
        </security:authentication-provider>
    </security:authentication-manager>

    <!-- Configure authorization -->
    <security:http auto-config="true">
        <security:intercept-url pattern="/" access="permitAll"/>
        <security:intercept-url pattern="/employees" access="hasRole('EMPLOYEE')"/>
        <security:intercept-url pattern="/leaders/**" access="hasRole('MANAGER')"/>
        <security:intercept-url pattern="/systems/**" access="hasRole('ADMIN')"/>
        <security:form-login login-page="/showMyLoginPage"
                             login-processing-url="/authenticateTheUser"
                             username-parameter="username"
                             password-parameter="password"
                             default-target-url="/" />
        <security:logout logout-success-url="/"
                         invalidate-session="true"
                         delete-cookies="JSESSIONID" />
    </security:http>

</beans>


<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:security="http://www.springframework.org/schema/security" xsi:schemaLocation="
					 http://www.springframework.org/schema/beans 
					 http://www.springframework.org/schema/beans/spring-beans.xsd
					 http://www.springframework.org/schema/security 
					 http://www.springframework.org/schema/security/spring-security.xsd">

	<security:http>
		<security:intercept-url pattern="/" access="permitAll()" />
		<security:intercept-url pattern="/employees" access="hasRole('EMPLOYEE')" />
		<security:intercept-url pattern="/leaders/" access="hasRole('MANAGER')" />
		<security:intercept-url pattern="/systems/" access="hasRole('ADMIN')" />
		<security:form-login login-page="/showMyLoginPage" login-processing-url="/authenticateTheUser" permit-all="true" />
		<security:logout logout-success-url="/" permit-all="true" />
	</security:http>

	<security:authentication-manager>
		<security:authentication-provider>
			<security:user-service>
				<security:user name="john" password="test123" authorities="EMPLOYEE" />
				<security:user name="mary" password="test123" authorities="EMPLOYEE, MANAGER" />
				<security:user name="susan" password="test123" authorities="EMPLOYEE, ADMIN" />
			</security:user-service>
		</security:authentication-provider>
	</security:authentication-manager>

</beans>
 */




