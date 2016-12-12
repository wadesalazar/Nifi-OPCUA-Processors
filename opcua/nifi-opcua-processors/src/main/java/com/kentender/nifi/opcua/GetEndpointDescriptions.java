package com.kentender.nifi.opcua;

import static org.opcfoundation.ua.utils.EndpointUtil.selectByProtocol;
import static org.opcfoundation.ua.utils.EndpointUtil.selectBySecurityPolicy;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Locale;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.exception.ProcessException;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.application.SessionChannel;
import org.opcfoundation.ua.builtintypes.ExpandedNodeId;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.BrowseDescription;
import org.opcfoundation.ua.core.BrowseDirection;
import org.opcfoundation.ua.core.BrowseRequest;
import org.opcfoundation.ua.core.BrowseResponse;
import org.opcfoundation.ua.core.BrowseResult;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.IdType;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.ReferenceDescription;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CertificateUtils;

public class GetEndpointDescriptions extends AbstractProcessor {
	
	final static String PRIVKEY_PASSWORD = "Opc.Ua";
	final Locale ENGLISH = Locale.ENGLISH;
	static int max_recursiveDepth = 4;
	static int recursiveDepth = 0;
	static StringBuilder stringBuilder = new StringBuilder();
	
	@Override
	public void onTrigger(ProcessContext arg0, ProcessSession arg1) throws ProcessException {
		// TODO Auto-generated method stub
		// Create Client
		//String url = "opc.tcp://192.168.189.10:49320/";
		String url = "opc.tcp://amalthea:21381/MatrikonOpcUaWrapper";
		
		// Load Client's Application Instance Certificate from file
		KeyPair myClientApplicationInstanceCertificate = getCert("Client");
		KeyPair myHttpsCertificate = getHttpsCert("Client");
		
		// Create Client
		Client myClient = Client.createClientApplication( myClientApplicationInstanceCertificate ); 
		myClient.getApplication().getHttpsSettings().setKeyPair(myHttpsCertificate);
		myClient.getApplication().addLocale( ENGLISH );
		myClient.getApplication().setApplicationName( new LocalizedText("YOUR APPLICATION NAME", Locale.ENGLISH) );
		myClient.getApplication().setProductUri( "urn:yourapplicationname" );
		
		//select an endpoint
		EndpointDescription[] endpoints = null;
		try {
			endpoints = myClient.discoverEndpoints(url);
		} catch (ServiceResultException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		endpoints = selectByProtocol(endpoints, "opc.tcp");
		endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC128RSA15);
		
		//System.out.println(SecurityPolicy.NONE);
		
		SessionChannel mySession = null;
		try {
			mySession = myClient.createSessionChannel(endpoints[0]);
			mySession.activate();	
		} catch (ServiceResultException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
			
		// Set up browse request
		BrowseRequest browseRequest = new BrowseRequest();
		BrowseResponse browseResponse = new BrowseResponse();
		BrowseResult[] browseResults = null;
		
		// Describe the request for parent node
		BrowseDescription[] NodesToBrowse = new BrowseDescription[1];
		NodesToBrowse[0] = new BrowseDescription();
		NodesToBrowse[0].setBrowseDirection(BrowseDirection.Forward);
		NodesToBrowse[0].setNodeId(Identifiers.RootFolder);
		browseRequest.setNodesToBrowse(NodesToBrowse);
		
		try {
			browseResponse = mySession.Browse(browseRequest);
			browseResults = browseResponse.getResults();
		} catch (ServiceFaultException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ServiceResultException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		ReferenceDescription[] referenceDesc = browseResults[0].getReferences();
		
		if(referenceDesc != null){
			
			for(int i = 0; i < referenceDesc.length; i++){
				System.out.println(referenceDesc[i].getNodeId());
				stringBuilder.append(referenceDesc[i].getNodeId() + System.lineSeparator());
				printTree(mySession, referenceDesc[i].getNodeId());
			}
		}
		
		File f=new File("c:writeContentfile.txt");
        
        StringBuffer sb = new StringBuffer("Text Content to write in java file");
        try{
            FileWriter fwriter = new FileWriter(f);
            BufferedWriter bwriter = new BufferedWriter(fwriter);
            bwriter.write(stringBuilder.toString());
            bwriter.close();
         }
        catch (Exception e){
              e.printStackTrace();
        }
		
	}
	
private static void printTree(SessionChannel sessionChannel, ExpandedNodeId expandedNodeId){
		
		if(expandedNodeId == null){
			return;
			
		}
		
		recursiveDepth++;
		
		// Describe the request for given node
		BrowseDescription[] NodesToBrowse = new BrowseDescription[1];
		
		// Set node to browse to given Node
		NodesToBrowse[0] = new BrowseDescription();
		NodesToBrowse[0].setBrowseDirection(BrowseDirection.Forward);
		
		if(expandedNodeId.getIdType() == IdType.String){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (String) expandedNodeId.getValue()) );
		}else if(expandedNodeId.getIdType() == IdType.Numeric){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (UnsignedInteger) expandedNodeId.getValue()) );
		}else if(expandedNodeId.getIdType() == IdType.Guid){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (UUID) expandedNodeId.getValue()) );
		}else if(expandedNodeId.getIdType() == IdType.Opaque){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (byte[]) expandedNodeId.getValue()) );
		}
		
		// Form request
		BrowseRequest browseRequest = new BrowseRequest();
		browseRequest.setNodesToBrowse(NodesToBrowse);
		
			
		// Form response, make request 
		BrowseResponse browseResponse = new BrowseResponse();
		try {
			browseResponse = sessionChannel.Browse(browseRequest);
		} catch (ServiceFaultException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServiceResultException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Get results
		BrowseResult[] browseResults = browseResponse.getResults();
		
		if (browseResults.length > 0 || browseResults == null){ 
			
		}
		
		// Retrieve reference descriptions for the result set 
		// 0 index is assumed 
		ReferenceDescription[] referenceDesc = browseResults[0].getReferences();
		
		// Situation 1: There are no result descriptions because we have hit a leaf
		if(referenceDesc == null){
			recursiveDepth--;
			return;
		}
		
		// Situation 2: There are results descriptions and each node must be parsed
		for(int k = 0; k < referenceDesc.length; k++){
			
			if (recursiveDepth > max_recursiveDepth){
				
				// If we have reached the defined max depth then break this loop ( avoids infinite recursion )
				break;
			}else {
				
				//Print indentation	
				for(int j = 0; j < recursiveDepth; j++){
					System.out.print("-");
				}
				
				// Print the current node
				System.out.println(referenceDesc[k].getNodeId());
				stringBuilder.append(referenceDesc[k].getNodeId() + System.lineSeparator());
				
				// Print the child node
				printTree(sessionChannel, referenceDesc[k].getNodeId());
			}
		
		}
		
		
		// we have exhausted the child nodes of the given node
		recursiveDepth--;
		return;
		
	}
	
	
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
