/**
 * 
 */
package expresionesRegulares;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author JoseManuel
 *
 */
public class Regex {

	
	public static boolean hasLetters(String s){
		boolean res = false;
		//Comprobar si tiene 1 o mas letras de a-z y A-Z
		Pattern p = Pattern.compile("^[a-zA-Z]+$");
		Matcher m = p.matcher(s);
		if(m.matches()){
			res = true;
		}
		return res;
	}
	
	
	public static boolean whiteListCharacters(String s){
		boolean res = false;
		//Similar a "^\\w+$", pero en este caso no se tendrían en cuenta los caracteres españoles
		Pattern p = Pattern.compile("^[a-zA-Z_0-9ñÑáéíóúÁÉÍÓÚ]+$");
		Matcher m = p.matcher(s);
		if(m.matches()){
			res = true;
		}
		return res;
	}
	
	public static boolean checkLowcaseUpcaseDigit(String s){
		boolean res = false;
		Pattern p = Pattern.compile("(?=.*[a-z]+)(?=.*[A-Z]+)(?=.*[0-9]+)"); // ([a-z]+)([A-Z]+)([0-9]+)
		Matcher m = p.matcher(s);
		while(m.find()){
			System.out.println("Found a lowercase "+m.group(0));
			//System.out.println("Found a lowercase "+m.group(1));
			//System.out.println("Found a lowercase "+m.group(2));
			res = true;
		}
		return res;
	}
	
	//Whitelist check for passwords
	/*True --> follows password policy
	False --> does NOT follow password policy
	*/
	public static boolean passwordCheck(String password){
		boolean res = false;
		/*Explicacion del patron
		 * (?=.*[a-z]+) --> contenga una o mas letras minusculas
		 * (?=.*[A-Z]+) --> contenga una o mas letras mayusculas
		 * (?=.*[0-9]+) --> contenga uno o mas digitos
		 * [a-zA-Z_0-9]{8,160} --> sea una palabra de longitud minima 8 y maxima 160 con los caracteres [a-zA-Z_0-9]
		 * 
		 * */
		Pattern p = Pattern.compile("(?=.*[a-z]+)(?=.*[A-Z]+)(?=.*[0-9]+)[a-zA-Z_0-9]{8,160}");
		/*En caso de seguir con el patron español,
		 * la regex quedaría: "(?=.*[a-záéíóúñ]+)(?=.*[A-ZÁÉÍÓÚÑ]+)(?=.*[0-9]+)[a-zA-Z_0-9áéíóúñÁÉÍÓÚÑ]{8,160}"*/
		Matcher m = p.matcher(password);
		if(m.matches()){
			res = true;
		}
		return res;
	}
	
	
	public static boolean basicEmailCheck(String email){
		boolean res = false;
		Pattern p = Pattern.compile("^[a-zA-Z_0-9.%+-]+@[a-zA-Z_0-9.-]+.[a-zA-Z]{2,}$");
		Matcher m = p.matcher(email);
		if(m.matches()){
			res = true;
		}
		return res;
	}
	
	public static boolean emailCheck(String email){
		boolean res = false;
		Pattern p = Pattern
				.compile("^[a-zA-Z0-9!#$%&'*+-/=?^_`{|}~][a-zA-Z0-9!#$%&'*+-/=?^_`{|}~.]{1,63}@"
						+ "[a-zA-Z0-9-]{1,125}.[a-z]{2,63}$");
		Matcher m = p.matcher(email);
		if(m.matches()){
			res = true;
		}
		return res;
	}
	
	
	public static boolean characterBlacklist(String s){
		boolean res = false;
		Pattern p = Pattern.compile("[^<>%^$/;\"]+");
		Matcher m = p.matcher(s);
		if(m.matches()){
			res = true;
		}
		return res;
	}
	

}
