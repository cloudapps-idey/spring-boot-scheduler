package example.com.metrics;

import org.apache.commons.io.FileUtils;
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

import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

@Service
@PropertySource("classpath:/application.properties")
public class ScheduledTasks {

    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasks.class);
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

     
    @Value("${expiry.alert.trigger.days}")
    private Integer expiryAlertTriggerDays;

    @Value("${expiry.alert.receiver.email.address}")
    private String expiryAlertReceiverEmailaddress;

    @Value("${expiry.cert.staging.path}")
    private String expiryCertStagingPath;

    @Value("${mock.vault}")
    private String mockVault;

    @Value("${cronSchedule}")
    private String cronSchedule;

    @Autowired
    ResourceLoader resourceLoader;

    @Autowired
    private JavaMailSender mailSender;

    @Scheduled(cron = "${cronSchedule}" )
    public void scheduleTaskWithCronExpression() {
        retrieveCertFromVaultForStaging(); 
        checkCertificateInKeyStore();
        checkCertificateInPem();
        cleanUpStagingDirectory();
    }

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
                    int daysLeft = Integer.valueOf(daysLeftToExpire(expiryDate));
                    if ( (daysLeft - expiryAlertTriggerDays) <=  expiryAlertTriggerDays){
                        logger.info("KEYSTORE FILE: Sending email. Days to epxiry is : " + daysLeft);
                        logger.info("KEYSTORE FILE: sending email");
                        sendEmail(expiryAlertReceiverEmailaddress, "Certificate expiry", "Certificate " + alias + " expires on " + ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter());
                    }
                    else{
                        logger.info("KEYSTORE FILE: No email expiry days left: " + daysLeft  + " expiry trigger days: " + expiryAlertTriggerDays + " days");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("\nKEYSTORE FILE: certificate check Ends");
    } 
    
    public void checkCertificateInPem() {

        logger.info("\n\nPEM FILE: Certificate check starts" + dateTimeFormatter.format(LocalDateTime.now()));
        File folder = new File(expiryCertStagingPath);
        File[] listOfFiles = folder.listFiles();
        logger.debug("PEM FILE:  No of Certificates = " + listOfFiles.length);
        InputStream inStream = null;

        try { 
            for (int i = 0; i < listOfFiles.length; i++) {

                if (listOfFiles[i].isFile()) {
            
                    inStream = new FileInputStream(listOfFiles[i]);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                    Date expiryDate = (Date) cert.getNotAfter();
                    //String ext = FilenameUtils.getExtension(listOfFiles[i].getName());
                    logger.debug("PEM FILE: Name of the File being scanned  :: " +listOfFiles[i].getName());
                    logger.info("PEM FILE: Certificate expires on " + expiryDate);
                    int daysLeft = Integer.valueOf(daysLeftToExpire(expiryDate));
                    int timeToTriggerDays = daysLeft - expiryAlertTriggerDays;
                    if ( (daysLeft - expiryAlertTriggerDays) <=  expiryAlertTriggerDays){
                        logger.info("PEM FILE: Sending email. Days to epxiry is : " + daysLeft + "triggerDays before: " + expiryAlertTriggerDays);                      
                        sendEmail(expiryAlertReceiverEmailaddress, "Certificate expiry", "Certificate expires on " + expiryDate);
                    }
                    else{
                        logger.info("PEM FILE: No email, days left to expire:" + daysLeft  + " expiry trigger days: " + expiryAlertTriggerDays + " days");
                        logger.info("PEM FILE: email will be send when  " + timeToTriggerDays + " days left");
                    }   
                }
            }            
        } catch (CertificateException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("\nPEM FILE: certificate check Ends");
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
}