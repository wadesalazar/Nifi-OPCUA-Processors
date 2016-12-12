/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kentender.nifi.opcua;

import static org.opcfoundation.ua.utils.EndpointUtil.selectByProtocol;
import static org.opcfoundation.ua.utils.EndpointUtil.selectBySecurityPolicy;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.*;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.io.OutputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.application.SessionChannel;
import org.opcfoundation.ua.builtintypes.DataValue;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.Attributes;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.ReadRequest;
import org.opcfoundation.ua.core.ReadResponse;
import org.opcfoundation.ua.core.ReadValueId;
import org.opcfoundation.ua.core.TimestampsToReturn;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CertificateUtils;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@Tags({"OPC", "OPCUA", "UA"})
@CapabilityDescription("Fetches a response from an OPC UA server based on configured name space and input item names")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
@InputRequirement(Requirement.INPUT_REQUIRED)


public class FetchOPCUA extends AbstractProcessor {
	
	public static final Locale ENGLISH = Locale.ENGLISH;
	
	// Create Client
	Client myClient = null;
	EndpointDescription[] endpoints = null;
	SessionChannel mySession = null;
	ReadResponse res = null;
	
	//TODO obviously needs to be handled by a property
	private static final String PRIVKEY_PASSWORD = "Opc.Ua";
	

	public static final PropertyDescriptor ENDPOINT = new PropertyDescriptor
            .Builder().name("Endpoint URL")
            .description("the opc.tcp address of the opc ua server")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor SECURITY_POLICY = new PropertyDescriptor
            .Builder().name("Security Policy")
            .description("How should Nifi authenticate with the UA server")
            .required(true)
            .allowableValues("None", "Basic128Rsa15", "Basic256", "Basic256Rsa256")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor CLIENT_CERT = new PropertyDescriptor
            .Builder().name("Client Certificate")
            .description("Certificate to identify the client when connecting to the UA server")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor PROTOCOL = new PropertyDescriptor
            .Builder().name("Transfer Protocol")
            .description("How should Nifi communicate with the OPC server")
            .required(true)
            .allowableValues("opc.tcp", "http")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor PREFIX = new PropertyDescriptor
            .Builder().name("Target prefix")
            .description("Identify the device and channel to be used ")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
      
    public static final PropertyDescriptor NAMESPACE = new PropertyDescriptor
            .Builder().name("Namespace")
            .description("Integer value of name space to read from")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final Relationship SUCCESS = new Relationship.Builder()
            .name("Success")
            .description("Successful OPC read")
            .build();
    
    public static final Relationship FAILURE = new Relationship.Builder()
            .name("FAILURE")
            .description("Failed OPC read")
            .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(ENDPOINT);
        descriptors.add(SECURITY_POLICY);
        descriptors.add(CLIENT_CERT);
        descriptors.add(PREFIX);
        descriptors.add(NAMESPACE);
        descriptors.add(PROTOCOL);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<Relationship>();
        relationships.add(SUCCESS);
        relationships.add(FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {
    	
    	final ComponentLog logger = getLogger();
		
		updateEndpoints(context);
		
		// Create Client
		myClient.getApplication().addLocale( ENGLISH );
		myClient.getApplication().setApplicationName( new LocalizedText("Java Sample Client", Locale.ENGLISH) );
		myClient.getApplication().setProductUri( "urn:NifiClient" );
		myClient.setTimeout( 10000 );
		
	}

    /* (non-Javadoc)
     * @see org.apache.nifi.processor.AbstractProcessor#onTrigger(org.apache.nifi.processor.ProcessContext, org.apache.nifi.processor.ProcessSession)
     */
    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    	
    	final ComponentLog logger = getLogger();
    	
    	//Init response variable
        final AtomicReference<String> reqTagname = new AtomicReference<>();
        final AtomicReference<String> serverResponse = new AtomicReference<>();
        
        
        FlowFile flowFile = session.get();
        if ( flowFile == null ) {
            return;
        }
        
      // Read tag name from flow file content
        session.read(flowFile, new InputStreamCallback() {
            @Override
            public void process(InputStream in) throws IOException {
            	
                try{
                	String tagname = new BufferedReader(new InputStreamReader(in))
                	  .lines().collect(Collectors.joining("\n"));

                    reqTagname.set(tagname);
                    
                }catch (Exception e) {
        			// TODO Auto-generated catch block
        			e.printStackTrace();
        		}
        		
            }
            
        });
        
        // Build nodes to read string 
        String nodeId = "ns=" 
				+ context.getProperty(NAMESPACE).getValue()
				+ ";s="
				+ context.getProperty(PREFIX).getValue()
				+ "."
				+ reqTagname.get();
        
        ReadValueId[] NodesToRead = { 
				new ReadValueId(NodeId.parseNodeId(nodeId), Attributes.Value, null, null ),
		};
        
        // Form OPC request
  		ReadRequest req = new ReadRequest();		
  		req.setMaxAge(500.00);
  		req.setTimestampsToReturn(TimestampsToReturn.Both);
  		req.setRequestHeader(null);
  		req.setNodesToRead(NodesToRead);

  		// Create and activate session
  		
  		/*
  		 * This needs to be maintained by a service 
  		 * with connection reference passed in the processor instance
  		 * 
  		 * */ 
  		
  		try {
  			// TODO pick a method for handling situations where more than one end point remains
  			mySession = myClient.createSessionChannel(endpoints[0]);
  			mySession.activate();
  			
  		} catch (ServiceResultException e1) {
  			// TODO Auto-generated catch block THIS NEEDS TO FAIL IN A SPECIAL WAY TO BE RE TRIED 
  			e1.printStackTrace();
  		}
  					
  		// Submit OPC Read and handle response
  		try{
          	res = mySession.Read(req);
              DataValue[] values = res.getResults();
              // TODO need to check the result for errors and other quality issues
              serverResponse.set(reqTagname.get() + "," + values[0].getValue().toString()  + ","+ values[0].getServerTimestamp().toString() );
              
          }catch (Exception e) {
  			// TODO Auto-generated catch block
  			e.printStackTrace();
  			session.transfer(flowFile, FAILURE);
  		}
  		
        // Write the results back out to flow file
        flowFile = session.write(flowFile, new OutputStreamCallback() {

            @Override
            public void process(OutputStream out) throws IOException {
            	out.write(serverResponse.get().getBytes());
            	
            }
            
        });
        
        session.transfer(flowFile, SUCCESS);
        
        // Close the session 
        
        /*
         * ( is this necessary or common practice.  
         * Timeouts clean up abandoned sessions ??? )*
         */
        
        try {
			mySession.close();
		} catch (ServiceFaultException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServiceResultException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
    }
    
    public void updateEndpoints(final ProcessContext context){
    	
    	final ComponentLog logger = getLogger();
    	
 		try {
 			
 			// Retrieve selected discovery URL an end point
			String url = context.getProperty(ENDPOINT).getValue();
			
			// Handle the selection of security policy
			
			if (context.getProperty(SECURITY_POLICY).getValue() == "None"){
				// Build OPC Client
				myClient = Client.createClientApplication( null );
				
				// Retrieve End point List
				endpoints = myClient.discoverEndpoints(url);
				
				// Filter end points based on selected policy
				endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.NONE);
				
			} else {
				
				KeyPair myClientApplicationInstanceCertificate = null;
				KeyPair myHttpsCertificate = null;
				String client_cert = context.getProperty(CLIENT_CERT).getValue();
				
				myHttpsCertificate = getHttpsCert("NifiHClient");
				
				switch (context.getProperty(SECURITY_POLICY).getValue()) {
					
 				case "Basic128Rsa15":{
 					
 					// Load or create Client's Application Instance Certificate and key
 					if (client_cert != null){
 						logger.debug(client_cert + " is the current cert being used");
 						myClientApplicationInstanceCertificate = getCert(client_cert);
 	 				} else {
 						logger.debug("Setting security policy to Basic 128");
 						myClientApplicationInstanceCertificate = getCert("NifiClient", SecurityPolicy.BASIC128RSA15);
 	 				}
 					
 					// Build OPC Client
 					myClient = Client.createClientApplication( myClientApplicationInstanceCertificate );
 					myClient.getApplication().getHttpsSettings().setKeyPair(myHttpsCertificate);
 					
 					// Retrieve End point List
 					endpoints = myClient.discoverEndpoints(url);
 					
 					// Filter end points based on selected policy
 					endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC128RSA15);
 					
 					break;
 					
 				}
 				
 				case "Basic256": {
 					
 					// Load or create HTTP and Client's Application Instance Certificate and key
 					if (client_cert != null){
 						logger.debug(client_cert + " is the current cert being used");
 						myClientApplicationInstanceCertificate = getCert(client_cert);
 	 				} else {
 						logger.debug("Setting security policy to Basic 256");
 						myClientApplicationInstanceCertificate = getCert("NifiClient", SecurityPolicy.BASIC256);
 	 				}
 					
 					// Build OPC Client
 					myClient = Client.createClientApplication( myClientApplicationInstanceCertificate );
 					myClient.getApplication().getHttpsSettings().setKeyPair(myHttpsCertificate);
 					
 					// Retrieve End point List
 					endpoints = myClient.discoverEndpoints(url);
 					
 					// Filter end points based on selected policy
 					endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC256);
 					
 					break;
 					
 				}
 				
 				case "Basic256Rsa256": {
 					
 					// Load or create HTTP and Client's Application Instance Certificate and key
 					if (client_cert != null){
 						logger.debug(client_cert + " is the provided certificate is being used");
 						myClientApplicationInstanceCertificate = getCert(client_cert);
 	 				} else {
 						logger.debug("Setting security policy to Basic 256");
 						myClientApplicationInstanceCertificate = getCert("NifiClient", SecurityPolicy.BASIC256);
 	 				}
 					
 					// Build OPC Client
 					myClient = Client.createClientApplication( myClientApplicationInstanceCertificate );
 					myClient.getApplication().getHttpsSettings().setKeyPair(myHttpsCertificate);
 					
 					// Retrieve End point List
 					endpoints = myClient.discoverEndpoints(url);
 					
 					// Filter end points based on selected policy
 					endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC256SHA256);
 					
 					break;
 					
 				}}
				
			}
			
			// Filter based on protocol selection
			endpoints = selectByProtocol(endpoints, "opc.tcp");
 			
 		} catch (ServiceResultException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
    }    
    
    public static KeyPair getCert(String applicationName) {
    	
    	//create a key pair - I have changed the original .pem extension to .key
  		return getCert(applicationName, SecurityPolicy.NONE);
			
	}
	
    
    public static KeyPair getCert(String applicationName, org.opcfoundation.ua.transport.security.SecurityPolicy securityPolicy) {
    	
    	//create a key pair - I have changed the original .pem extension to .key
  		return getCert(applicationName, applicationName + ".der", applicationName + ".key", securityPolicy);
			
	}
    
    public static KeyPair getCert(String applicationName, String cert, String key, org.opcfoundation.ua.transport.security.SecurityPolicy securityPolicy) {
		
		File certFile = new File(cert);
		File privKeyFile =  new File(key);
		
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
			try {
				String hostName = InetAddress.getLocalHost().getHostName();
				String applicationUri = "urn:"+hostName+":"+"NifiClient";
				
				/**
				 * Define the algorithm to use for certificate signatures.
				 * <p>
				 * The OPC UA specification defines that the algorithm should be (at least)
				 * "SHA1WithRSA" for application instance certificates used for security
				 * policies Basic128Rsa15 and Basic256. For Basic256Sha256 it should be
				 * "SHA256WithRSA".
				 * <p>
				 */
				
				if(securityPolicy == SecurityPolicy.BASIC128RSA15){
					CertificateUtils.setKeySize(1024);
					CertificateUtils.setCertificateSignatureAlgorithm("SHA1WithRSA");
				} else if(securityPolicy == SecurityPolicy.BASIC256) {
					CertificateUtils.setKeySize(2028);
					CertificateUtils.setCertificateSignatureAlgorithm("Basic256");
				} else if(securityPolicy == SecurityPolicy.BASIC256SHA256){
					CertificateUtils.setKeySize(2028);
					CertificateUtils.setCertificateSignatureAlgorithm("SHA256WithRSA");
				} else {
					//nothing to do yet
				}
				
				KeyPair keys = CertificateUtils.createApplicationInstanceCertificate(applicationName, "your.fqhn.org", applicationUri, 3650, hostName);
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
		File certFile = new File("NifiCA.der");
		File privKeyFile =  new File("NifiCA.pem");
		try {
			Cert myServerCertificate = Cert.load( certFile );
			PrivKey myServerPrivateKey = PrivKey.load( privKeyFile, PRIVKEY_PASSWORD );
			return new KeyPair(myServerCertificate, myServerPrivateKey); 
		} catch (CertificateException e) {
			System.out.println(e.toString());
		} catch (IOException e) {		
			try {
				KeyPair keys = CertificateUtils.createIssuerCertificate("NifiCA", 3650, null);
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
