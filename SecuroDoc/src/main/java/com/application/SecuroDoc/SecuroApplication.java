package com.application.SecuroDoc;

import com.application.SecuroDoc.Repository.RoleRepo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableJpaAuditing
@EnableAsync
public class SecuroApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuroApplication.class, args);
	}

	@Bean
	ApplicationRunner applicationRunner(@Value("${spring.datasource.url}") String datasource){
		return args -> {
			System.out.println("Data from Secret's Manager : " + datasource);
		};
	}

	@Bean
	CommandLineRunner commandLineRunner(RoleRepo roleRepo){


		return args -> {
//			RequestContext.setUserId(0L);
//			var userRole = new RoleEntity();
//			userRole.setName(Authority.USER.name());
//			userRole.setAuthorities(Authority.USER);
//			roleRepo.save(userRole);
//
//			var adminRole = new RoleEntity();
//			adminRole.setName(Authority.ADMIN.name());
//			adminRole.setAuthorities(Authority.ADMIN);
//			roleRepo.save(adminRole);
//			RequestContext.start();
		};
	}

}
