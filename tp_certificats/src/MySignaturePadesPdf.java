import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Scanner;

public class MySignaturePadesPdf {
    private Certificate privateKeyCertificate;
    private PrivateKey privateKey;
    private Certificate[] certificateChain;

    public static final String SRC_PDF = "monPdf";

    public MySignaturePadesPdf(String pP12File, String pMotDePasse){
        // Le manageur crypto BouncyCastle est ajouté comme fournisseur de sécurité
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Chargement du fichier de certificate PKCS12 en utilisant BC (Bouncy Castle)
            KeyStore keystore = KeyStore.getInstance("pkcs12", "BC");
            // Chargement du fichier avec le mot de passe en 2ème paramètre
            keystore.load(new FileInputStream(pP12File), pMotDePasse.toCharArray());

            // test all aliases
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()){
                String a = aliases.nextElement();
                if (keystore.isKeyEntry(a)){
                    this.privateKeyCertificate = keystore.getCertificate(a);
                    this.privateKey = (PrivateKey)keystore.getKey(a, pMotDePasse.toCharArray());
                    this.certificateChain = keystore.getCertificateChain(a);
                }
            }


        } catch (FileNotFoundException e){
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public void generatePdf(){
        try {
            PdfWriter pdfwriter = new PdfWriter(SRC_PDF);
            PdfDocument pdfdocument = new PdfDocument(pdfwriter);
            Document document = new Document(pdfdocument);

            String texte = "Je vais signer un fichier PDF";
            document.add(new Paragraph(texte));

            document.close();
            System.out.println("Nouveau PDF généré avec succès");


        } catch (FileNotFoundException e){
            e.printStackTrace();
        }
    }


    public void getCertificate(){
        System.out.println(this.privateKeyCertificate);
    }


    public void signerPdf(String pOutfile, String pRaisonSignature, String pLieuSignature){
        try {
            FileOutputStream fos = new FileOutputStream(new File(pOutfile));
            PdfReader pdfReader = new PdfReader(SRC_PDF + ".pdf");
            /*PdfPadesSigner pdfPadesSigner = new PdfPadesSigner(pdfReader, fos);
            SignerProperties sp = new SignerProperties()
                    .setLocation(pLieuSignature)
                    .setReason(pRaisonSignature);*/

            PdfSigner pdfSigner = new PdfSigner(pdfReader, fos, new StampingProperties().useAppendMode());

            Rectangle signatureRect = new Rectangle(36, 700, 200, 100); // Position et taille (x, y, width, height)
            PdfSignatureAppearance signatureAppearance = pdfSigner.getSignatureAppearance();
            signatureAppearance
                    .setLocation("Brest")
                    .setReason("is THIS a reason?")
                    .setPageRect(signatureRect) // Position sur le PDF
                    .setPageNumber(1)
                    .setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION); // Signature visible

            pdfSigner.setFieldName("Signature");


            IExternalSignature padesSignature = new PrivateKeySignature(this.privateKey, DigestAlgorithms.SHA256, "BC");
            IExternalDigest digest = new BouncyCastleDigest();

            // Signature
            pdfSigner.signDetached(digest, padesSignature, this.certificateChain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);


            //pdfPadesSigner.signWithBaselineBProfile(sp, this.certificateChain, this.privateKey);

        } catch (Exception e){
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        System.out.println("Entrer le mot de passe");
        Scanner scanner = new Scanner(System.in);
        String pwd = scanner.nextLine();
        String filename = "PrenomNom_cert_sign.p12";

        MySignaturePadesPdf pdf = new MySignaturePadesPdf(filename, pwd);
        pdf.getCertificate();

        pdf.generatePdf();
    }
}
