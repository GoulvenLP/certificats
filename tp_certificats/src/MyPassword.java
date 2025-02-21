import util.ByteToHex;

import java.util.HexFormat;
import java.util.Scanner;
import java.security.MessageDigest;

public class MyPassword {

    private String password;

    /**
     * Stores the password in a hashed SHA-256 format
     * @param password
     */
    public MyPassword(String password){
        byte[] bPassword = hacheSha256(password);
        this.password = ByteToHex.convert(bPassword);
    }

    /**
     * getter
     * @return the password as a String
     */
    public String getPassword(){
        return this.password;
    }

    public String toString(){
        return "Mot de passe stocké : " + this.password;
    }

    public boolean equals(Object pPass) {
        return this.password.equals(((MyPassword) pPass).getPassword());
    }

    public boolean controleAcces(String pPass){
        MyPassword myPasswordControleAcces = new MyPassword(pPass);
        return myPasswordControleAcces.equals(this);
    }

    public static byte[] hacheSha256(String pMessage){
        byte[] hashedPassword = null;
        byte[] passwordBytes = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            passwordBytes = pMessage.getBytes("UTF-8");
            hashedPassword = md.digest(passwordBytes);
        } catch (Exception e){
            e.printStackTrace();
        }
        return hashedPassword;
    }

    public static void main(String[] args) {
        // definition mot de passe
        System.out.println("Veuillez définir un mot de passe : ");
        Scanner scanner = new Scanner( System.in );
        String passString = scanner.nextLine();

        // instanciation
        MyPassword mp = new MyPassword(passString);

        // connexion: vérification mdp
        System.out.println("Veuillez saisir votre mot de passe pour vous connecter : ");
        String confirmation = scanner.nextLine();

        if (mp.controleAcces(confirmation)){
            System.out.println("Succes");
        } else {
            System.out.println("Échec");
        }

        String sig = "Je signe un message électroniquement";
        MyFirstSignature mfs = new MyFirstSignature(sig);

        System.out.println("La signature du message : [" + sig + "] est :");
        System.out.println(ByteToHex.convert(mfs.sign()));

        boolean lValide = mfs.verifySignature(mfs.sign());
        System.out.println( "La signature est " + ( lValide ? "Valide" : "Invalide" ) );

        MySecondSignature mss = new MySecondSignature(sig);
        System.out.println(ByteToHex.convert(mss.sign()));

        boolean lValide2 = mss.verifySignature(mss.sign());
        System.out.println( "La signature est " + ( lValide2 ? "Valide" : "Invalide" ) );


    }
}
