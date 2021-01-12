package tuto.spring.security.students;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementConroller {
	
	private List<Student> STUDENTS = Arrays.asList(
			new Student(1, "Mohammed Aoulad Bouchta"),
			new Student(2, "Bilal Souri"),
			new Student(3, "Hamza Chouté"));
	
	
	@PostMapping
	@PreAuthorize("hasAuthority('student:write')")
	public String addStudent(@RequestBody Student student) {
		return "student was added";
	}
	
	@DeleteMapping(path = "/{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public String deleteStudent(@PathVariable("studentId") Integer studentId) {
		return "student was deleted";
	}
	
	@PutMapping(path = "/{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public String updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
		return "student was updated";
	}
	
	@GetMapping
	@PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
	public List<Student> allStudents(){
		return STUDENTS;
	}
}
