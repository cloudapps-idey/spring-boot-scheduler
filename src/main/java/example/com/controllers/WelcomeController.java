package example.com.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
@RequestMapping("welcome")
public class WelcomeController {


	@GetMapping("message")
	public ResponseEntity<String> getCategories() {

		String welcomeMessage="Hello World from 'simplest-spring-boot-app' !!!";
		System.out.println("welcome message is :" + welcomeMessage);
		return new ResponseEntity<String>(welcomeMessage, HttpStatus.OK);
	}
}
