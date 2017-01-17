package com.kentender.nifi.opcua;

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
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.SecurityPolicy;

@Tags({"OPC", "OPCUA", "UA"})
@CapabilityDescription("Fetches a response from an OPC UA server based on configured name space and input item names")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})

public class GetEndpoints extends AbstractProcessor{

	public static final Locale ENGLISH = Locale.ENGLISH;
	
	static Client myClient = null;
	static EndpointDescription[] endpointDescriptions = null;
	static SessionChannel mySession = null;
	
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
		myClient.getApplication().addLocale( ENGLISH );
		myClient.getApplication().setApplicationName( new LocalizedText(context.getProperty(APPLICATION_NAME).getValue(), Locale.ENGLISH) );
		myClient.getApplication().setProductUri( "urn:" + context.getProperty(APPLICATION_NAME).getValue() );
		
	}

    /* (non-Javadoc)
     * @see org.apache.nifi.processor.AbstractProcessor#onTrigger(org.apache.nifi.processor.ProcessContext, org.apache.nifi.processor.ProcessSession)
     */
    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    	
    	final ComponentLog logger = getLogger();
    	StringBuilder stringBuilder = new StringBuilder();
        
        // Retrieve end point list
 		try {
 			endpointDescriptions = null;
 			endpointDescriptions = myClient.discoverEndpoints(context.getProperty(ENDPOINT).getValue());
 		} catch (ServiceResultException e1) {
 			
 			logger.error(e1.getMessage());
 		}
 		
        
        for (int i = 0; i < endpointDescriptions.length; i++){
        	stringBuilder.append(endpointDescriptions[i].getEndpointUrl() + " - " + endpointDescriptions[i].getSecurityPolicyUri()  + " - " + endpointDescriptions[i].getSecurityMode() + System.lineSeparator());
        	
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
