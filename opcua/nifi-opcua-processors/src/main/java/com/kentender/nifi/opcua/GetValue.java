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
import org.apache.nifi.annotation.lifecycle.OnUnscheduled;
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
import org.opcfoundation.ua.builtintypes.ServiceRequest;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.ActivateSessionRequest;
import org.opcfoundation.ua.core.ActivateSessionResponse;
import org.opcfoundation.ua.core.Attributes;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.ReadRequest;
import org.opcfoundation.ua.core.ReadResponse;
import org.opcfoundation.ua.core.ReadValueId;
import org.opcfoundation.ua.core.TimestampsToReturn;
import org.opcfoundation.ua.transport.SecureChannel;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

@Tags({"OPC", "OPCUA", "UA"})
@CapabilityDescription("Fetches a response from an OPC UA server based on configured name space and input item names")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
@InputRequirement(Requirement.INPUT_REQUIRED)


public class GetValue extends AbstractProcessor {
	
	// Create Client
	private static Client myClient = null;
	private static SessionChannel mySession = null;
	private static EndpointDescription endpointDescription = null;

	public static final PropertyDescriptor ENDPOINT = new PropertyDescriptor
            .Builder().name("Endpoint URL")
            .description("the opc.tcp address of the opc ua server")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
	
	public static final PropertyDescriptor SERVER_CERT = new PropertyDescriptor
            .Builder().name("Certificate for Server application")
            .description("Certificate in .der format for server Nifi will connect, if left blank Nifi will attempt to retreive the certificate from the server")
            .addValidator(StandardValidators.FILE_EXISTS_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor SECURITY_POLICY = new PropertyDescriptor
            .Builder().name("Security Policy")
            .description("How should Nifi authenticate with the UA server")
            .required(true)
            .allowableValues("None", "Basic128Rsa15", "Basic256", "Basic256Rsa256")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor APPLICATION_NAME = new PropertyDescriptor
    		.Builder().name("Application Name")
            .description("The application name is used to label certificates identifying this application")
            .required(false)
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
	private byte[] myNonce;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(ENDPOINT);
        descriptors.add(SECURITY_POLICY);
        descriptors.add(APPLICATION_NAME);
        descriptors.add(SERVER_CERT);
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
    	EndpointDescription[] endpointDescriptions = null;
    	
    	KeyPair myClientApplicationInstanceCertificate = null;
    	KeyPair myHttpsCertificate = null;
    	
    	// Load Client's certificates from file or create new certs
		if (context.getProperty(SECURITY_POLICY).getValue() == "None"){
			// Build OPC Client
			myClientApplicationInstanceCertificate = null;
						
		} else {

			myHttpsCertificate = Utils.getHttpsCert(context.getProperty(APPLICATION_NAME).getValue());
			
			// Load or create HTTP and Client's Application Instance Certificate and key
			switch (context.getProperty(SECURITY_POLICY).getValue()) {
				
				case "Basic128Rsa15":{
					myClientApplicationInstanceCertificate = Utils.getCert(context.getProperty(APPLICATION_NAME).getValue(), SecurityPolicy.BASIC128RSA15);
					break;
					
				}case "Basic256": {
					myClientApplicationInstanceCertificate = Utils.getCert(context.getProperty(APPLICATION_NAME).getValue(), SecurityPolicy.BASIC256);
					break;
					
				}case "Basic256Rsa256": {
					myClientApplicationInstanceCertificate = Utils.getCert(context.getProperty(APPLICATION_NAME).getValue(), SecurityPolicy.BASIC256SHA256);
					break;
				}
			}
		}
		
		// Create Client
		myClient = Client.createClientApplication( myClientApplicationInstanceCertificate ); 
		myClient.getApplication().getHttpsSettings().setKeyPair(myHttpsCertificate);
		myClient.getApplication().addLocale( Locale.ENGLISH );
		myClient.getApplication().setApplicationName( new LocalizedText(context.getProperty(APPLICATION_NAME).getValue(), Locale.ENGLISH) );
		myClient.getApplication().setProductUri( "urn:" + context.getProperty(APPLICATION_NAME).getValue() );
		
		// if a certificate is provided
		if (context.getProperty(SERVER_CERT).getValue() != null){
			Cert myOwnCert = null;
			
			// if a certificate is provided
			try {
				File myCertFile = new File(context.getProperty(SERVER_CERT).getValue());
				myOwnCert = Cert.load(myCertFile);
				
			} catch (CertificateException e1) {
				logger.debug(e1.getMessage());
			} catch (IOException e1) {
				logger.debug(e1.getMessage());
			}
			
			// Describe end point
			endpointDescription = new EndpointDescription();
			endpointDescription.setEndpointUrl(context.getProperty(ENDPOINT).getValue());
			endpointDescription.setServerCertificate(myOwnCert.getEncoded());
			endpointDescription.setSecurityMode(MessageSecurityMode.Sign);
			switch (context.getProperty(SECURITY_POLICY).getValue()) {
				case "Basic128Rsa15":{
					endpointDescription.setSecurityPolicyUri(SecurityPolicy.BASIC128RSA15.getPolicyUri());
					break;
				}
				case "Basic256": {
					endpointDescription.setSecurityPolicyUri(SecurityPolicy.BASIC256.getPolicyUri());
					break;
				}	
				case "Basic256Rsa256": {
					endpointDescription.setSecurityPolicyUri(SecurityPolicy.BASIC256SHA256.getPolicyUri());
					break;
				}
				default :{
					endpointDescription.setSecurityPolicyUri(SecurityPolicy.NONE.getPolicyUri());
					logger.error("No security mode specified");
					break;
				}
			}
			
	 		
			
		} else {
			try {
				endpointDescriptions = myClient.discoverEndpoints(context.getProperty(ENDPOINT).getValue());
			} catch (ServiceResultException e1) {

				logger.error(e1.getMessage());
			}
			switch (context.getProperty(SECURITY_POLICY).getValue()) {
			
				case "Basic128Rsa15":{
					endpointDescriptions = selectBySecurityPolicy(endpointDescriptions,SecurityPolicy.BASIC128RSA15);
					break;
				}
				case "Basic256": {
					endpointDescriptions = selectBySecurityPolicy(endpointDescriptions,SecurityPolicy.BASIC256);
					break;
				}	
				case "Basic256Rsa256": {
					endpointDescriptions = selectBySecurityPolicy(endpointDescriptions,SecurityPolicy.BASIC256SHA256);
					break;
				}
				default :{
					endpointDescriptions = selectBySecurityPolicy(endpointDescriptions,SecurityPolicy.NONE);
					logger.error("No security mode specified");
					break;
				}
			}
			
			// For now only opc.tcp has been implemented
			endpointDescriptions = selectByProtocol(endpointDescriptions, "opc.tcp");
			
			// set the provided end point url to match the given one ( for local host problem )
	 		// endpoints[0].setEndpointUrl(url);
			endpointDescription = endpointDescriptions[0].clone();
	 	}
	
		
		try {
			mySession = myClient.createSessionChannel(endpointDescription);
		} catch (ServiceResultException e) {
			// TODO Auto-generated catch block
			logger.debug("Error while creating initial SessionChannel: ");
			logger.error(e.getMessage());
		}
		
	}

    @OnUnscheduled
	public void onUnscheduled(final ProcessContext context){
    	final ComponentLog logger = getLogger();
    	
    	
    	

    }
    
    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    	
    	final ComponentLog logger = getLogger();
    	
    	// Test session and if closed create and activate new session 
    	try {
    		mySession.activate();
  		} catch (ServiceResultException e1) {
  			
  			logger.debug("The session " + mySession.getSession().getAuthenticationToken() + " has timed out.");
  			try {
  				logger.debug("Creating new session");
				mySession = myClient.createSessionChannel(endpointDescription);
				mySession.activate();
			} catch (ServiceResultException e) {
				logger.debug("Error while creating new session: ");
				logger.error(e.getMessage());
			}
  			
  		}
    	
    	    	
    	// Initialize  response variable
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
                	logger.error(e.getMessage());
        		}
        		
            }
            
        });
        
        // Build nodes to read string 

        ReadValueId[] NodesToRead = { 
				new ReadValueId(NodeId.parseNodeId(reqTagname.get()), Attributes.Value, null, null )
		};
        
        // Form OPC request
  		ReadRequest req = new ReadRequest();		
  		req.setMaxAge(500.00);
  		req.setTimestampsToReturn(TimestampsToReturn.Both);
  		req.setRequestHeader(null);
  		req.setNodesToRead(NodesToRead);

  		// Submit OPC Read and handle response
  		try{
  			ReadResponse readResponse = mySession.Read(req);
            DataValue[] values = readResponse.getResults();
            // TODO need to check the result for errors and other quality issues
            serverResponse.set(reqTagname.get() + "," + values[0].getValue().toString()  + ","+ values[0].getServerTimestamp().toString() );
              
          }catch (Exception e) {
        	logger.error(e.getMessage());
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
        
    }
    
}
