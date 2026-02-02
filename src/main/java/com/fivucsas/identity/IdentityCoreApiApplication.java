package com.fivucsas.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class IdentityCoreApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityCoreApiApplication.class, args);
    }

}
