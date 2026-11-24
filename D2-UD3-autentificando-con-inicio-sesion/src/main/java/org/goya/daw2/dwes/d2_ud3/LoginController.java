package org.goya.daw2.dwes.d2_ud3;

import java.util.Map;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Controller
public class LoginController {

	// Nombre del atributo de sesión donde guardamos al usuario autenticado
	private static final String USUARIO = "usuario";

	// Objeto que sabe comprobar una contraseña contra su hash BCrypt
	private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

	// Usuarios válidos: nombre -> contraseña HASHEADA con BCrypt.
	// Las contraseñas en claro NO están en el código (ver README / documentación).
	// Los hashes se generan con la clase GeneradorHash.
	private final Map<String, String> usuarios = Map.of(
			"admin",  "$2a$10$EM96kamBOALs8H/lqwqg9ucv88ug2CRWZtdKOq1EN/N0/XTzLTaI6",
			"alumno", "$2a$10$X1bcbzOYlDzm0t34JMLbteSuP9A0R6Sl.0qwuXl1bnOSvngOPcjdi",
			"profe",  "$2a$10$hhQHDWHxPS8QpGlrtwxQ/.CyovvBbfqMGMlrd1UhS1T81ZfkLPEde");

	// ---------- Páginas protegidas: /, /pagina1 y /pagina2 ----------

	@GetMapping("/")
	public String inicio(HttpSession session, HttpServletResponse response, Model model) {
		return mostrarPagina("inicio", session, response, model);
	}

	// Se aceptan las dos formas: con tilde (como pide el enunciado) y sin ella
	@GetMapping({ "/pagina1", "/página1" })
	public String pagina1(HttpSession session, HttpServletResponse response, Model model) {
		return mostrarPagina("página1", session, response, model);
	}

	@GetMapping({ "/pagina2", "/página2" })
	public String pagina2(HttpSession session, HttpServletResponse response, Model model) {
		return mostrarPagina("página2", session, response, model);
	}

	/**
	 * Lógica común de las tres páginas protegidas:
	 * - sin sesión iniciada  -> redirige a /login (punto 2.1)
	 * - con sesión iniciada  -> muestra la plantilla común "pagina" (punto 2.2)
	 */
	private String mostrarPagina(String pagina, HttpSession session, HttpServletResponse response, Model model) {
		String usuario = (String) session.getAttribute(USUARIO);
		if (usuario == null) {
			return "redirect:/login";
		}
		// Que el navegador no guarde la página en caché: así, tras cerrar sesión,
		// el botón "Atrás" no puede mostrarla sin volver a preguntar al servidor
		response.setHeader("Cache-Control", "no-store");

		model.addAttribute("usuario", usuario);
		model.addAttribute("pagina", pagina);
		return "pagina";
	}

	// ---------- Login ----------

	@GetMapping("/login")
	public String formularioLogin(HttpSession session) {
		// 3.1: si ya inició sesión, se comporta como el punto 2.2
		if (session.getAttribute(USUARIO) != null) {
			return "redirect:/";
		}
		// 3.2: si no, muestra el formulario
		return "login";
	}

	@PostMapping("/login")
	public String procesarLogin(@RequestParam String usuario,
	                            @RequestParam String password,
	                            HttpSession session, Model model) {
		String hashGuardado = usuarios.get(usuario);

		// 3.3: usuario existe y la contraseña coincide con su hash
		if (hashGuardado != null && encoder.matches(password, hashGuardado)) {
			session.setAttribute(USUARIO, usuario);
			return "redirect:/";
		}

		// 3.4: datos incorrectos -> error y se vuelve a mostrar el formulario
		model.addAttribute("error", "Usuario o contraseña incorrectos");
		model.addAttribute("usuarioEscrito", usuario);
		return "login";
	}

	// ---------- Logout (nivel "Bien") ----------

	@GetMapping("/logout")
	public String logout(HttpSession session) {
		session.invalidate(); // borra la sesión y todo lo que contiene
		return "redirect:/login";
	}
}