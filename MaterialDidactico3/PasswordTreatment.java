/**
 * 
 */
package argon2_jvm;
import de.mkammerer.argon2.*;
/**
 * @author JoseManuel
 *
 */

public class PasswordTreatment {

	//Crear instancia de Argon2i personalizada
	private static Argon2 createInstanceArgon2i(int saltlength, int outputlength){
		return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i,saltlength, outputlength);
	}
	
	//Crear instancia de Argon2d personalizada
	private static Argon2 createInstanceArgon2d(int saltlength, int outputlength){
		return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2d,saltlength, outputlength);
	}
	
	//Crear instancia de Argon2id personalizada
	private static Argon2 createInstanceArgon2id(int saltlength, int outputlength){
		return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id,saltlength, outputlength);
	}
	
	/*Método protect especificando los parámetros a emplear
	 * 	password: String que se hashea
	 * 	iterations: iteraciones del algoritmo
	 * 	memory: memoria a emplear
	 * 	thread: grado de paralelización
	 * 	type: tipo de Argon2, 0->Argon2i ; 1->Argon2d ; 2->Argon2id
	 * 	saltlength: longitud del salt a emplear
	 * 	outputlength: longitud del hash de salida*/
	public static String protect(char[] password, int iterations, int memory, int threads, int type, int saltlength, int outputlength){
		Argon2 argon2hasher= null;
		String argon2hash;
		try{
			//Crear instancia de Argon2
			switch(type){
				case 0:
					argon2hasher = createInstanceArgon2i(saltlength,outputlength);break;
				case 1:
					argon2hasher = createInstanceArgon2d(saltlength,outputlength);break;
				case 2:
					argon2hasher = createInstanceArgon2id(saltlength,outputlength);break;
				default:
					System.out.println("Unkown option, setted to Argon2i due to authors recommendation");
					argon2hasher = createInstanceArgon2i(saltlength,outputlength);
			}
			//Hashear la contraseña
			argon2hash = argon2hasher.hash(iterations, memory, threads, password);
		}finally{
			//Borrar contraseña de memoria
			if(argon2hasher != null)
				argon2hasher.wipeArray(password);
		}
		return argon2hash;
	}
	
	//Método similar a protect(), solo que calcula las iteraciones para que el algoritmo de Argon2
	//tarde como máximo 'miliseconds' milisegundos en calcular el hash
	public static String protectAided(char[] password, int miliseconds, int memory, int threads, int type, int saltlength, int outputlength){
		Argon2 argon2hasher= null;
		String argon2hash;
		int iterations;
		try{
			//Crear instancia de Argon2
			switch(type){
				case 0:
					argon2hasher = createInstanceArgon2i(saltlength,outputlength);break;
				case 1:
					argon2hasher = createInstanceArgon2d(saltlength,outputlength);break;
				case 2:
					argon2hasher = createInstanceArgon2id(saltlength,outputlength);break;
				default:
					System.out.println("Unkown option, setted to Argon2i due to authors recommendation");
					argon2hasher = createInstanceArgon2i(saltlength,outputlength);
			}
			//Obtener número de iteraciones óptimo para el sistema teniendo en cuenta el tiempo máximo
			iterations = Argon2Helper.findIterations(argon2hasher, miliseconds, memory, threads);
			//Hashear la contraseña
			argon2hash = argon2hasher.hash(iterations, memory, threads, password);
		}finally{
			//Borrar contraseña de memoria
			if(argon2hasher != null)
				argon2hasher.wipeArray(password);
		}
		return argon2hash;
	}
	
	//Método para verificar el hash con la contraseña introducida, se necesita saber el tipo de Argon2 empleado
	public static boolean verify(String hash, char[] password, int type, int saltlength, int outputlength){
		Argon2 argon2hasher = null;
		boolean matches;
		try{
			//Crear instancia de Argon2
			switch(type){
				case 0:
					argon2hasher = createInstanceArgon2i(saltlength,outputlength);break;
				case 1:
					argon2hasher = createInstanceArgon2d(saltlength,outputlength);break;
				case 2:
					argon2hasher = createInstanceArgon2id(saltlength,outputlength);break;
				default:
					System.out.println("Unkown option, setted to Argon2i due to authors recommendation");
					argon2hasher = createInstanceArgon2i(saltlength,outputlength);
			}
			//Verificar el hash
			matches = argon2hasher.verify(hash, password);
		}finally{
			//Borrar contraseña de memoria
			if(argon2hasher != null)
				argon2hasher.wipeArray(password);
		}
		return matches;
	}
	
	public static void main(String[] args) {
		String pass = "password123";
		//Argon2i, con un máximo de 1000 milisegundos. Una longitud de 16 bytes de salt y 16 bytes de longitud de salida
		String argoned = protectAided(pass.toCharArray(),1000,65536,2,0,16,16);
		System.out.println(argoned);
		System.out.println("Verification is: "+verify(argoned,pass.toCharArray(),0,16,16));
	}

}
