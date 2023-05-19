package example.com;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@ComponentScan
@EnableAutoConfiguration
@EnableScheduling
public class Application extends SpringBootServletInitializer {

    public static void main(String[] args) {
    	 SpringApplication.run(Application.class, args);
    }
}