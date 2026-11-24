package org.goya.daw2.dwes.d2_ud3;

import java.util.Scanner;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Utilidad para generar el hash BCrypt de una contraseña.
 * En Eclipse: botón derecho sobre esta clase -> Run As -> Java Application,
 * escribe la contraseña en la consola y pulsa Intro.
 * Copia el hash que aparece al mapa "usuarios" de LoginController.
 *
 * Cada ejecución da un hash distinto (BCrypt usa una "sal" aleatoria),
 * pero todos sirven para comprobar la misma contraseña.
 */
public class GeneradorHash {

	public static void main(String[] args) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		try (Scanner teclado = new Scanner(System.in)) {
			System.out.print("Contraseña a hashear: ");
			String contrasena = teclado.nextLine();
			System.out.println("Hash BCrypt: " + encoder.encode(contrasena));
		}
	}
}