package dndhelper;

import dndhelper.config.security.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class DndhelperApplication {

	public static void main(String[] args) {
		SpringApplication.run(DndhelperApplication.class, args);
	}

}
