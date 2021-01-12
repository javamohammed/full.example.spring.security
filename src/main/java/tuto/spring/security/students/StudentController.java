package tuto.spring.security.students;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

	private List<Student> STUDENTS = Arrays.asList(
				new Student(1, "Mohammed Aoulad Bouchta"),
				new Student(2, "Bilal Souri"),
				new Student(3, "Hamza Chouté"));
	
	@GetMapping(path = "/{id}")
	public Student getStudent(@PathVariable("id") Integer id) {

		return STUDENTS.stream()
					.filter(student -> id.equals(student.getId()))
					.findFirst()
					.orElseThrow(()->new IllegalStateException("This Student doesnot exists "));
	}
}
