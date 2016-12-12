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

import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
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
	
	
	final Locale ENGLISH = Locale.ENGLISH;
	static int max_recursiveDepth = 4;
	static int recursiveDepth = 0;
	static StringBuilder stringBuilder = new StringBuilder();
	
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
		

		
	}
	
	@Override
	public void onTrigger(ProcessContext arg0, ProcessSession arg1) throws ProcessException {
		// TODO Auto-generated method stub
		// Create Client
		//String url = "opc.tcp://192.168.189.10:49320/";
		String url = "opc.tcp://amalthea:21381/MatrikonOpcUaWrapper";
		
		// Load Client's Application Instance Certificate from file
		KeyPair myClientApplicationInstanceCertificate = Utils.getCert("Client");
		KeyPair myHttpsCertificate = Utils.getHttpsCert("Client");
		
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
				parseNodeTree(mySession, referenceDesc[i].getNodeId());
			}
		}
		
		File f=new File("writeContentfile.txt");
        
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
	
private static void parseNodeTree(SessionChannel sessionChannel, ExpandedNodeId expandedNodeId){
		
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
					stringBuilder.append("- ");
				}
				stringBuilder.append(System.lineSeparator());
				
				// Print the current node
				stringBuilder.append(referenceDesc[k].getNodeId() + System.lineSeparator());
				
				// Print the child node
				parseNodeTree(sessionChannel, referenceDesc[k].getNodeId());
			}
		
		}
		
		
		// we have exhausted the child nodes of the given node
		recursiveDepth--;
		return;
		
	}
	
	
	
}
