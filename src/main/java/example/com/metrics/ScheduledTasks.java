package example.com.metrics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.security.cert.X509Certificate ;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

@Component
public class ScheduledTasks {

    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasks.class);
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

     
    @Value("${expiry.alert.trigger.days}")
    private Integer expiryAlertTriggerDays;

    @Value("${expiry.alert.receiver.email.address}")
    private String expiryAlertReceiverEmailaddress;

    @Autowired
    ResourceLoader resourceLoader;

    @Autowired
    private JavaMailSender mailSender;

    @Scheduled(cron = "0 * * * * *")
    public void scheduleTaskWithCronExpression() {
        
        checkCertificateInKeyStore();
        logger.info("Cron Task :: Execution Time - {}", dateTimeFormatter.format(LocalDateTime.now()));
    }

    public void checkCertificateInKeyStore(){

        logger.info("certificate check starts");

        try {            
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new ClassPathResource("classpath:test.jks").getInputStream(), "password".toCharArray());
            Enumeration<String> aliases = keyStore.aliases();

            while(aliases.hasMoreElements()){

                String alias = aliases.nextElement();
                if(keyStore.getCertificate(alias).getType().equals("X.509")){            
                    logger.info("Certificate " + alias + " expires on " + ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter());
                    Date expiryDate =  ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter();
                    int daysLeft = Integer.valueOf(daysLeftToExpire(expiryDate));
                    if( daysLeft <= expiryAlertTriggerDays ) {
                        logger.info("Sending email. Days to epxiry is : " + daysLeft);
                        logger.info("sending email");
                        sendEmail(expiryAlertReceiverEmailaddress, "Certificate expiry", "Certificate " + alias + " expires on " + ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter());
                    }
                    else{
                        logger.info("Not sending email. Days to epxiry is : " + daysLeft  + " which is greater than the configured expiryAlertTriggerDays of  " + expiryAlertTriggerDays + " days");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } 
        logger.info("certificate check Ends");
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
           logger.info("expiryDate " + expiryDate + " Today's date: " + now);
           logger.info("expiryDate " + expiryDate.getTime() + " Today's date: " + now.getTime());
           long diffInMillies = Math.abs(expiryDate.getTime() - now.getTime());
           diff = TimeUnit.DAYS.convert(diffInMillies, TimeUnit.MILLISECONDS);
        }
        catch(Exception e){
           logger.error(e.getMessage());
           //e.getStackTrace();
        }
        return String.valueOf(diff);           
    }    
}