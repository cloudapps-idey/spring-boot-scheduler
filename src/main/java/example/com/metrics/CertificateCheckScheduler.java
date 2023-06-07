package example.com.metrics;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate ;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

@Service
@PropertySource("classpath:/application.properties")
public class CertificateCheckScheduler {

    private static final Logger logger = LoggerFactory.getLogger(CertificateCheckScheduler.class);
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

     
    @Value("${expiry.alert.trigger.days}")
    private Integer expiryAlertTriggerDays;

    @Value("${expiry.alert.receiver.email.address}")
    private String expiryAlertReceiverEmailaddress;

    @Value("${expiry.cert.staging.path}")
    private String expiryCertStagingPath;

    @Value("${mock.vault}")
    private String mockVault;

    @Autowired
    ResourceLoader resourceLoader;

    @Autowired
    private JavaMailSender mailSender;

    @Scheduled(cron = "${cronSchedule}" )
    public void scheduleTaskWithCronExpression() {
        retrieveCertFromVaultForStaging(); 
        checkCertificateInKeyStore();
        checkCertificateInPemSingle();
        //checkCertificateInPem();
        cleanUpStagingDirectory();
        checkCertificateInBase64String(); 
    }

    //check cert in a JKS file
    public void checkCertificateInKeyStore(){

        logger.info("\n\nKEYSTORE FILE: Certificate check starts at " + dateTimeFormatter.format(LocalDateTime.now()));
        //logger.info("\n\nKEYSTORE FILE: Cron Task :: Execution Time .p12 file- {}", dateTimeFormatter.format(LocalDateTime.now()));

        try {            
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new ClassPathResource("./test.p12").getInputStream(), "password".toCharArray());
            Enumeration<String> aliases = keyStore.aliases();
            
            while(aliases.hasMoreElements()){

                String alias = aliases.nextElement();
                if(keyStore.getCertificate(alias).getType().equals("X.509")){            
                    logger.info("KEYSTORE FILE:  " + alias + " expires on " + ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter());
                    Date expiryDate =  ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter();
                    processEmailAlert(expiryDate, "KEYSTORE FILE", alias, "");    
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("\nKEYSTORE FILE: certificate check Ends");
    } 

    

    //Check on a single pem file
    public void checkCertificateInPemSingle()  {

        logger.info("\n\nPEM FILE: Certificate check starts" + dateTimeFormatter.format(LocalDateTime.now()));
        try { 
            InputStream inStream = new ClassPathResource("./mock-vault/vault-file.pem").getInputStream();                 
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            Date expiryDate = (Date) cert.getNotAfter();
            processEmailAlert(expiryDate, "KEYSTORE FILE", "", cert.getSubjectX500Principal().getName());                         
        } catch (CertificateException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("\nPEM FILE: certificate check Ends");
    } 
    
    //Check on multiple Certificates in a directory
    public void checkForMultipleCertificatesInDirectory()  {

        logger.info("\n\nPEM FILE: Certificate check starts" + dateTimeFormatter.format(LocalDateTime.now()));
        try { 
            //File folder = new ClassPathResource(expiryCertStagingPath).getFile();
            File folder = new File(expiryCertStagingPath);
            File[] listOfFiles = folder.listFiles();
            logger.debug("PEM FILE:  No of Certificates = " + listOfFiles.length);
            InputStream inStream = null;
        
            for (int i = 0; i < listOfFiles.length; i++) {

                if (listOfFiles[i].isFile()) {
            
                    inStream = new FileInputStream(listOfFiles[i]);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                    Date expiryDate = (Date) cert.getNotAfter();
                    String ext = FilenameUtils.getExtension(listOfFiles[i].getName());
                    logger.debug("PEM FILE: Name of the File being scanned  :: " +listOfFiles[i].getName());
                    processEmailAlert(expiryDate, ext + " FILE", "", cert.getSubjectX500Principal().getName());    
                }
            }            
        } catch (IOException e) {
            e.printStackTrace();
        }catch (CertificateException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("\nPEM FILE: certificate check Ends");
    } 

    public void checkCertificateInBase64String()  {

        logger.info("\n\nBase64String: Certificate check starts" + dateTimeFormatter.format(LocalDateTime.now()));

        String certB64 = getCertInBase64Encoding();
        logger.debug("certB64 " + getCertInBase64Encoding()); 
        try { 
            byte encodedCert[] = Base64.getDecoder().decode(certB64);
            ByteArrayInputStream inputStream  =  new ByteArrayInputStream(encodedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inputStream);   
            Date expiryDate = (Date) cert.getNotAfter();
            logger.info("Base64String:: Certificate expires on " + expiryDate); 
            processEmailAlert(expiryDate, "Base64String", "", cert.getSubjectX500Principal().getName());                        
        } catch (CertificateException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("\nBase64String:: certificate check Ends");
    } 

    public void processEmailAlert(Date expiryDate, String typeOfCertFile, String alias, String certPricinipalName){

        int daysLeft = Integer.valueOf(daysLeftToExpire(expiryDate));
        if ( (daysLeft - expiryAlertTriggerDays) <=  expiryAlertTriggerDays){
            logger.info(typeOfCertFile + ": Sending email. Days to epxiry is : " + daysLeft);
            sendEmail(expiryAlertReceiverEmailaddress, "ALERT : Certificate expiry approaching", "Certificate " + alias + " expires on " + expiryDate +
             " Please verify and take necessary precaution, only " + daysLeft + " days left to expire. \n Certificate Details: principal name: "  + certPricinipalName);
        }
        else{
            logger.info(typeOfCertFile + ": No email expiry days left: " + daysLeft  + " expiry trigger days: " + expiryAlertTriggerDays + " days");
        }
    }

    public void sendEmail(String to, String subject, String body) {

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }

    public String daysLeftToExpire (Date expiryDate){
        long diff = 0;
        try{
           Date now = new Date();
           long diffInMillies = Math.abs(expiryDate.getTime() - now.getTime());
           diff = TimeUnit.DAYS.convert(diffInMillies, TimeUnit.MILLISECONDS);
        }
        catch(Exception e){
           logger.error(e.getMessage());
        }
        return String.valueOf(diff);           
    } 
   
    void retrieveCertFromVaultForStaging(){
        logger.info("Retrieve certs from vault starts ");
        File sourceFolder = new File(mockVault);
        File destFolder = new File(expiryCertStagingPath);
        try{
        FileUtils.copyDirectory(sourceFolder, destFolder );
        }catch ( IOException e){
            e.printStackTrace();
        }
        logger.info("Retrieve certs from vault ends ");
    }
    
    void cleanUpStagingDirectory(){
        logger.info("Cleaning Staging Directory Starts");
        File destFolder = new File(expiryCertStagingPath);
        try{
        FileUtils.cleanDirectory(destFolder );
        }catch ( IOException e){
            e.printStackTrace();
        }
        logger.info("Cleaning Staging Directory Ends");
    }

    String getCertInBase64Encoding(){
        return new String ("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGZXpDQ0EyT2dBd0lCQWdJRWFvcys1akFOQmdrcWhraUc5dzBCQVF3RkFEQnVNUXN3Q1FZRFZRUUdFd0pWDQpVekVMTUFrR0ExVUVDQk1DVFVReEZUQVRCZ05WQkFjVERFSjFjblJ2Ym5OMmFXeHNaVEVRTUE0R0ExVUVDaE1IDQpVbVZrSUVoaGRERVRNQkVHQTFVRUN4TUtRMjl1YzNWc2RHbHVaekVVTUJJR0ExVUVBeE1MU1c1a2NtRnVhU0JFDQpaWGt3SGhjTk1qTXdOVEU1TWpBek16STRXaGNOTXpNd05URTJNakF6TXpJNFdqQnVNUXN3Q1FZRFZRUUdFd0pWDQpVekVMTUFrR0ExVUVDQk1DVFVReEZUQVRCZ05WQkFjVERFSjFjblJ2Ym5OMmFXeHNaVEVRTUE0R0ExVUVDaE1IDQpVbVZrSUVoaGRERVRNQkVHQTFVRUN4TUtRMjl1YzNWc2RHbHVaekVVTUJJR0ExVUVBeE1MU1c1a2NtRnVhU0JFDQpaWGt3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQ1Y4UHhlZlcvYXJxL2lGbnp6DQo5MDJ1MnRha2xKWk4zUGNtUHVsZXZyMWFBZlFVYXRkZ09xemY2cFR1MU9laEpOeHV1aEszZ0EvbjFwZlJldUlLDQpoaXA3UmE4VUxwbng0ZmFtR0FWQjdSb3cwbmpweGdmOHFhNXlGMm53QlNOaGl6Sm1KT0xRc2dLU2gyaWtOZnFuDQpPWHZJYmtYS1hJNXM3MTBmcUtXbVVpb2wyUEU4YS8zbEtLR2trekpKWkUySkhNcTUyQTJWSEc1bVBkUVVCWU5aDQowR25rVEhqOTlBWUplMkZRLzIzaWVBMWVpdGsyN1J0Tmo3MzdXUnBKVE5nc1dHWlYrdFd0T2loc2pZSzZvUE9rDQpKUWo3eGx1RVE5amNIV0NqWVR6RTZ4bGZmMGdwWWRSOGxTS2tSWHVvN3hZTlhJZEd4Y1l4MTR2bVArMWtQTDU4DQo5V1RqU3ArMnRkSEtudzl3RWZ6TXNWV3B3ak1KM2Nza2RhQUVnb2FMaU9IY2RLT2VhalFieHpxUGJJTnNJczZNDQp3bmE2cDV4VFFoazNzYUo0Q01hS3FSQ3ZFbm9BQVVSUkZmMnI4YnQ3VDVCSVdsNU1SRTJKeVBlTVpYSXZjTEllDQpZcE5ySjAzSWd0dzdEL3RsdUtIRlcwMnR5eXJacTFXOXl3b3dJam9nZEdremZSMDIxR1FmVHRkRHJTcWx2MjRWDQpXRFA5Q1pUSUl0WDhHL0tBT0xxK3IzamduY3FaQnVpK2FkbkN4US82NjdtL085S2tNL3RDTG1lNkQ0Z3YyMlgxDQpJRWwraHBrK1BOaVJmSDBSWDQ0TmtwNUh0aWFzd01SdWFKNUVMT1RuczE1YWIxVXFuUVhpRkQ2MXNFT1YyYzZyDQpMTWJLWXFlMGhIamwrOU1kMXBXdEVpaXhsUUlEQVFBQm95RXdIekFkQmdOVkhRNEVGZ1FVWnN3eXUvNXY5b3dSDQpraVVSNzJvZDJHVThxcm93RFFZSktvWklodmNOQVFFTUJRQURnZ0lCQUlEQmhmL0xTSDVSUXFCcFpsNWgvUERaDQp1bUN4bXFvKzduSlBEV3JTVk9raFVIY3hndnBJQXdOLzN6WFRCZzJpdlBrMHcxMy9rVU1PWTRVQ25MTkRZOEhVDQpLMTU1YWt3emcrcUV6TDVmZ1FxN0pCVVZ4dTZ3TlhXa2NGTmt6Q0U3ZUc4cTlXaDQwSVdRZXdxTUFqWVhseWhHDQpTVHl1MU13Sy95WGdaOUNLZHg2elByVTc5T1BWeFR1eDdCa2FNaHZWVVAwZW9zNUNKMlBVMlF1WEt2bXhLczZRDQpUa1FIZFVvV0I4Mithdkc0QWVTbEJvMnNQK25hNEpuQkZVTVgxMisyTmRjVmZCekZXTmNOL0ZQZllRSC9hY3c3DQp2bVRGQUZYaG5KYm03Y1l1Vm8ycmxsQnlsdmkzMWVaTjJQZGZ0YmdFZ1JPYWlsTFgyREI5bS94TXdMRk50NHIyDQpLSEVuZDVqSGNyRlo4R1JSUlEvcnE2bE5iS3FVcnlVRU91VHU5d2lTQnBYUWpGcHJOR3JETmV2eFIrWUdLeCtqDQo1NDFFRGdJNlNIbk8rZGNtYzJjNVQxVjdLOEVONnkvTkY0cmppelBjV3ZZMkdFL3haRnZSZVBWRC85L20vSDUyDQoyekd6WG5PSkZaNVZYak9kTWZ5dlEwNDVUVExxcFRJaGV6aEF2MjJjbXNlZ3p3Y3NIR1JyYWhQS0ZMN0Jad1pGDQovMU1ESVRibXk4MDgvREV5dHFqTmtYaENOMk45TGo5bmZ4OVI0Q2ZraXJwNURCQ2VIb2ZxWnZ1RVNjUUpQazFtDQpzcGxJc1kxTGFaeHlGeDF4TXo1UjhDOFJHZUsySG4vVjJ2d21Bc09veFZGQVZDU1pURzZ5QmpERnltdDRwRXlLDQpZK3NTcGdHZ2M3U2diQTJ6bTNWZA0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==");
    }
}