package com.kentender.nifi.opcua;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.utils.CertificateUtils;

public class Utils {
	
	final static String PRIVKEY_PASSWORD = "Opc.Ua";
	
	public static KeyPair getCert(String applicationName) {
		File certFile = new File(applicationName + ".der");
		File privKeyFile =  new File(applicationName+ ".pem");
		try {
			Cert myServerCertificate = Cert.load( certFile );
			PrivKey myServerPrivateKey = PrivKey.load( privKeyFile, PRIVKEY_PASSWORD );
			return new KeyPair(myServerCertificate, myServerPrivateKey); 
		} catch (CertificateException e) {
			System.out.println(e.toString());
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {		
			//System.out.println("got an exception opening cert so creating a new cert?");
			try {
				
				CertificateUtils.setKeySize(1024);
				CertificateUtils.setCertificateSignatureAlgorithm("SHA1WithRSA");
				
				String hostName = InetAddress.getLocalHost().getHostName();
				String applicationUri = "urn:"+hostName+":"+applicationName;
				KeyPair keys = CertificateUtils.createApplicationInstanceCertificate(applicationName, null, applicationUri, 3650, hostName);
				keys.getCertificate().save(certFile);
				keys.getPrivateKey().save(privKeyFile);
				return keys;
			} catch (Exception e1) {
				System.out.println(e1.toString());
			}
		}
		return null;
	}
	
	public static KeyPair getHttpsCert(String applicationName){
		File certFile = new File(applicationName + "_https.der");
		File privKeyFile =  new File(applicationName+ "_https.pem");
		try {
			Cert myServerCertificate = Cert.load( certFile );
			PrivKey myServerPrivateKey = PrivKey.load( privKeyFile, PRIVKEY_PASSWORD );
			return new KeyPair(myServerCertificate, myServerPrivateKey); 
		} catch (CertificateException e) {
			
			System.out.println(e.toString());
		} catch (NoSuchAlgorithmException e) {
			
			System.out.println(e.toString());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			
			System.out.println(e.toString());
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (IOException e) {	
			System.out.println(e.toString());
			System.out.println("got an exception so creating a new file?");
			try {
				KeyPair caCert = getCACert();
				String hostName = InetAddress.getLocalHost().getHostName();
				String applicationUri = "urn:"+hostName+":"+applicationName;
				KeyPair keys = CertificateUtils.createHttpsCertificate(hostName, applicationUri, 3650, caCert);
				keys.save(certFile, privKeyFile, PRIVKEY_PASSWORD);
				return keys;
			} catch (Exception e1) {
				System.out.println(e1.toString());
			}
		}
		return null;
	}
	
	public static KeyPair getCACert(){
		File certFile = new File("SampleCA.der");
		File privKeyFile =  new File("SampleCA.pem");
		try {
			Cert myServerCertificate = Cert.load( certFile );
			PrivKey myServerPrivateKey = PrivKey.load( privKeyFile, PRIVKEY_PASSWORD );
			return new KeyPair(myServerCertificate, myServerPrivateKey); 
		} catch (CertificateException e) {
			System.out.println(e.toString());
		} catch (IOException e) {		
			try {
				KeyPair keys = CertificateUtils.createIssuerCertificate("SampleCA", 3650, null);
				keys.getCertificate().save(certFile);
				keys.getPrivateKey().save(privKeyFile, PRIVKEY_PASSWORD);
				return keys;
			} catch (Exception e1) {
				System.out.println(e1.toString());
			}
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
