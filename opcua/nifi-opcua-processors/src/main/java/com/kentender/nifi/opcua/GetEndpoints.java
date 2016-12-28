package com.kentender.nifi.opcua;

import static org.opcfoundation.ua.utils.EndpointUtil.selectByProtocol;
import static org.opcfoundation.ua.utils.EndpointUtil.selectBySecurityPolicy;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.OutputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.application.SessionChannel;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.ReadResponse;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.EndpointUtil;

@Tags({"OPC", "OPCUA", "UA"})
@CapabilityDescription("Fetches a response from an OPC UA server based on configured name space and input item names")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})

public class GetEndpoints extends AbstractProcessor{

	// TODO add scope for vars
	public static final Locale ENGLISH = Locale.ENGLISH;
	static KeyPair myClientApplicationInstanceCertificate = null;
	static KeyPair myHttpsCertificate = null;
	static String applicationName = null;
	static String url = "";
	
	// Create Client
	Client myClient = null;
	EndpointDescription[] endpoints = null;
	SessionChannel mySession = null;
	ReadResponse res = null;

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
    
    // TODO change this to application and implement in the same manner as get endpoint
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

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(ENDPOINT);
        descriptors.add(SECURITY_POLICY);
        descriptors.add(APPLICATION_NAME);
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
    	
    	url = context.getProperty(ENDPOINT).getValue();
    	applicationName = context.getProperty(APPLICATION_NAME).getValue();
    	
		// Load Client's certificates from file or create new certs
		if (context.getProperty(SECURITY_POLICY).getValue() == "None"){
			// Build OPC Client
			myClientApplicationInstanceCertificate = null;
						
		} else {

			myHttpsCertificate = Utils.getHttpsCert(applicationName);
			
			// Load or create HTTP and Client's Application Instance Certificate and key
			switch (context.getProperty(SECURITY_POLICY).getValue()) {
				
				case "Basic128Rsa15":{
					myClientApplicationInstanceCertificate = Utils.getCert(applicationName, SecurityPolicy.BASIC128RSA15);
					break;
					
				}case "Basic256": {
					myClientApplicationInstanceCertificate = Utils.getCert(applicationName, SecurityPolicy.BASIC256);
					break;
					
				}case "Basic256Rsa256": {
					myClientApplicationInstanceCertificate = Utils.getCert(applicationName, SecurityPolicy.BASIC256SHA256);
					break;
				}
			}
		}
		
		// Create Client
		// TODO need to move this to service or on schedule method
		myClient = Client.createClientApplication( myClientApplicationInstanceCertificate ); 
		myClient.getApplication().getHttpsSettings().setKeyPair(myHttpsCertificate);
		myClient.getApplication().addLocale( ENGLISH );
		myClient.getApplication().setApplicationName( new LocalizedText(applicationName, Locale.ENGLISH) );
		myClient.getApplication().setProductUri( "urn:" + applicationName );
		
		
	}

    /* (non-Javadoc)
     * @see org.apache.nifi.processor.AbstractProcessor#onTrigger(org.apache.nifi.processor.ProcessContext, org.apache.nifi.processor.ProcessSession)
     */
    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    	
    	final ComponentLog logger = getLogger();
    	StringBuilder stringBuilder = new StringBuilder();
        
        // Retrieve and filter end point list
 		// TODO need to move this to service or on schedule method
 		
 		try {
 			endpoints = null;
 			endpoints = myClient.discoverEndpoints(url);
 		} catch (ServiceResultException e1) {
 			// TODO Auto-generated catch block
 			
 			logger.error(e1.getMessage());
 		}
 		
 		switch (context.getProperty(SECURITY_POLICY).getValue()) {
 			
 			case "Basic128Rsa15":{
 				endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC128RSA15);
 				break;
 			}
 			case "Basic256": {
 				endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC256);
 				break;
 			}	
 			case "Basic256Rsa256": {
 				endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.BASIC256SHA256);
 				break;
 			}
 			default :{
 				endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.NONE);
 				logger.error("No security mode specified");
 				break;
 			}
 		}
     		
 		// For now only opc.tcp has been implemented
 		endpoints = selectByProtocol(endpoints, "opc.tcp");
 		
 		// Finally confirm the provided end point is in the list
 		endpoints = EndpointUtil.selectByUrl(endpoints, url);
 		
 		logger.debug(endpoints.length + " endpoints found");
        
        for (int i = 0; i < endpoints.length; i++){
        	stringBuilder.append(endpoints[i].getEndpointUrl() + " - " + endpoints[i].getSecurityPolicyUri() + System.lineSeparator());
        	
        }
 		
        // Write the results back out to flow file
        FlowFile flowFile = session.create();
        flowFile = session.write(flowFile, new OutputStreamCallback() {

            @Override
            public void process(OutputStream out) throws IOException {
            	out.write(stringBuilder.toString().getBytes());
            	
            }
            
        });
        
        session.transfer(flowFile, SUCCESS);
    }
    
}
