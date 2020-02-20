package io.github.hobbstech.commons.springjwtsecurity;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Import(JwtSecurityConfiguration.class)
public @interface EnableJwtSecurity {
}
