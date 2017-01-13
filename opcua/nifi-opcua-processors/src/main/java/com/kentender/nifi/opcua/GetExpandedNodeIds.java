package com.kentender.nifi.opcua;

import static org.opcfoundation.ua.utils.EndpointUtil.selectByProtocol;
import static org.opcfoundation.ua.utils.EndpointUtil.selectBySecurityPolicy;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.lifecycle.OnUnscheduled;
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
import org.opcfoundation.ua.builtintypes.ExpandedNodeId;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.UnsignedByte;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.BrowseDescription;
import org.opcfoundation.ua.core.BrowseDirection;
import org.opcfoundation.ua.core.BrowseRequest;
import org.opcfoundation.ua.core.BrowseResponse;
import org.opcfoundation.ua.core.BrowseResult;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.IdType;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.ReferenceDescription;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CertificateUtils;

@Tags({"OPC", "OPCUA", "UA"})
@CapabilityDescription("Retrieves the namespace from an OPC UA server")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})

public class GetExpandedNodeIds extends AbstractProcessor {
	
	// TODO clean up static vars and implement private where needed
	static Client myClient = null;
	static SessionChannel mySession = null;
	
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
    
    public static final PropertyDescriptor STARTING_NODE = new PropertyDescriptor
            .Builder().name("Starting Node")
            .description("From what node should Nifi begin browsing the node tree. Default is the root node.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor RECURSIVE_DEPTH = new PropertyDescriptor
            .Builder().name("Recursive Depth")
            .description("Maxium depth from the starting node to read, Default is 1")
            .required(true)
            .addValidator(StandardValidators.INTEGER_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor APPLICATION_NAME = new PropertyDescriptor
            .Builder().name("Application Name")
            .description("The application name is used to label certificates identifying this application")
            .required(true)
            .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor OUTFILE_NAME = new PropertyDescriptor
            .Builder().name("Output filename")
            .description("File path and name used for output")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
	
    public static final PropertyDescriptor PRINT_INDENTATION = new PropertyDescriptor
            .Builder().name("Print Indentation")
            .description("Should Nifi add indentation to the output text")
            .required(true)
            .allowableValues("No", "Yes")
            .defaultValue("No")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final Relationship SUCCESS = new Relationship.Builder()
            .name("Success")
            .description("Successful OPC read")
            .build();
    
    public static final Relationship FAILURE = new Relationship.Builder()
            .name("Failure")
            .description("Failed OPC read")
            .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(ENDPOINT);
        descriptors.add(RECURSIVE_DEPTH);
        descriptors.add(SECURITY_POLICY);
        descriptors.add(SERVER_CERT);
        descriptors.add(STARTING_NODE);
        descriptors.add(APPLICATION_NAME);
        descriptors.add(OUTFILE_NAME);
        descriptors.add(PRINT_INDENTATION);

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
    	EndpointDescription endpointDescription = null;
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
		// TODO need to move this to service or on schedule method
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
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
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
				// TODO Auto-generated catch block
				
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
			endpointDescription =  endpointDescriptions[0].clone();
			// endpointDescription = EndpointUtil.selectByUrl(endpointDescriptions, url)[0];
	 	}
				
		logger.debug("Using endpoint: " + endpointDescription.toString());
		
		try {
			mySession = myClient.createSessionChannel(endpointDescription);
			mySession.activate();	
		} catch (ServiceResultException e1) {
			// TODO Auto-generated catch block
			logger.error(e1.getMessage());
		}
    }
    
    @OnUnscheduled
	public void onUnscheduled(final ProcessContext context){
    	final ComponentLog logger = getLogger();
    	
    	// Close the session 
        try {
			mySession.close();
		} catch (ServiceFaultException e) {
			// TODO Auto-generated catch block
			logger.error(e.getMessage());
		} catch (ServiceResultException e) {
			// TODO Auto-generated catch block
			logger.error(e.getMessage());
		}
        
        myClient = null;
    	mySession = null;
    }
    
	@Override
	public void onTrigger(ProcessContext context, ProcessSession session) throws ProcessException {
		
		final ComponentLog logger = getLogger();
		StringBuilder stringBuilder = new StringBuilder();
		
		// Set the starting node and parse the node tree
		if ( context.getProperty(STARTING_NODE).getValue() == null) {
			logger.debug("Parse the root node " + new ExpandedNodeId(Identifiers.RootFolder));
			stringBuilder.append(parseNodeTree(mySession, 
					context.getProperty(PRINT_INDENTATION).getValue(), 
					0, 
					Integer.valueOf(context.getProperty(RECURSIVE_DEPTH).getValue()), 
					new ExpandedNodeId(Identifiers.RootFolder)));
			
		} else {
			logger.debug("Parse the result list for node " + new ExpandedNodeId(NodeId.parseNodeId(context.getProperty(STARTING_NODE).getValue())));
			stringBuilder.append(parseNodeTree(mySession, 
					context.getProperty(PRINT_INDENTATION).getValue(), 
					0, 
					Integer.valueOf(context.getProperty(RECURSIVE_DEPTH).getValue()), 
					new ExpandedNodeId(NodeId.parseNodeId(context.getProperty(STARTING_NODE).getValue()))));
		}
		
		// Write the results back out to a flow file
		FlowFile flowFile = session.create();
        if ( flowFile == null ) {
        	logger.error("Flowfile is null");
        }
		
		flowFile = session.write(flowFile, new OutputStreamCallback() {
            public void process(OutputStream out) throws IOException {
            	out.write(stringBuilder.toString().getBytes());
            	
            }
		});
        
		// Transfer data to flow file
        session.transfer(flowFile, SUCCESS);
        
    }
	
	private static String parseNodeTree(SessionChannel mySession,
			String print_indentation, 
			int recursiveDepth, 
			int max_recursiveDepth, 
			ExpandedNodeId expandedNodeId){
		
		
		StringBuilder stringBuilder = new StringBuilder();
		
		// Conditions for exiting this function
		// If provided node is null ( should not happen )
		if(expandedNodeId == null){	return null; }
		
		// Have we already reached the max depth? Exit if so
		if (recursiveDepth > max_recursiveDepth){ return null; }
		
		// Describe the request for given node
		BrowseDescription[] NodesToBrowse = new BrowseDescription[1];
		NodesToBrowse[0] = new BrowseDescription();
		NodesToBrowse[0].setBrowseDirection(BrowseDirection.Forward);
		
		// Set node to browse to given Node
		if(expandedNodeId.getIdType() == IdType.String){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (String) expandedNodeId.getValue()) );
		}else if(expandedNodeId.getIdType() == IdType.Numeric){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (UnsignedInteger) expandedNodeId.getValue()) );
		}else if(expandedNodeId.getIdType() == IdType.Guid){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (UUID) expandedNodeId.getValue()) );
		}else if(expandedNodeId.getIdType() == IdType.Opaque){

			NodesToBrowse[0].setNodeId( new NodeId(expandedNodeId.getNamespaceIndex(), (byte[]) expandedNodeId.getValue()) );
		} else {
			// Return if no matches. Is this not a valid node?
		}
		
		// Form request
		BrowseRequest browseRequest = new BrowseRequest();
		browseRequest.setNodesToBrowse(NodesToBrowse);
		
		// Form response, make request 
		BrowseResponse browseResponse = new BrowseResponse();
		try {
			browseResponse = mySession.Browse(browseRequest);
		} catch (ServiceFaultException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServiceResultException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Get results
		BrowseResult[] browseResults = browseResponse.getResults();
		
		// Retrieve reference descriptions for the result set 
		// 0 index is assumed !!!
		ReferenceDescription[] referenceDesc = browseResults[0].getReferences();
		
		// Situation 1: There are no result descriptions because we have hit a leaf
		if(referenceDesc == null){
			return null;
		}
		
		// Situation 2: There are results descriptions and each node must be parsed
		for(int k = 0; k < referenceDesc.length; k++){
				
			// Print indentation	
			switch (print_indentation) {
			
				case "Yes":{
					for(int j = 0; j < recursiveDepth; j++){
						stringBuilder.append("- ");
					}
				}
			}
			
			// Print the current node
			stringBuilder.append(referenceDesc[k].getNodeId() + System.lineSeparator());
			
			// Print the child node(s)
			String str = parseNodeTree(mySession, print_indentation, recursiveDepth + 1, max_recursiveDepth, referenceDesc[k].getNodeId());
			if (str != null){
				stringBuilder.append(str);
			}
			
			
		}
		
		return stringBuilder.toString();
		
		// we have exhausted the child nodes of the given node
		
	}

}
