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

import static org.opcfoundation.ua.utils.EndpointUtil.selectByMessageSecurityMode;
import static org.opcfoundation.ua.utils.EndpointUtil.selectByProtocol;
import static org.opcfoundation.ua.utils.EndpointUtil.selectBySecurityPolicy;
import static org.opcfoundation.ua.utils.EndpointUtil.sortBySecurityLevel;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.PropertyValue;
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
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.Attributes;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.ReadRequest;
import org.opcfoundation.ua.core.ReadResponse;
import org.opcfoundation.ua.core.ReadValueId;
import org.opcfoundation.ua.core.TimestampsToReturn;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import  org.opcfoundation.ua.utils.EndpointUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

@Tags({"OPC", "OPCUA", "UA"})
@CapabilityDescription("Fetches a response from an OPC UA server based on configured name space and input item names")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
@InputRequirement(Requirement.INPUT_REQUIRED)


public class FetchOPCUA extends AbstractProcessor {
	
	// Create Client
	Client myClient = Client.createClientApplication(null);
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
            .allowableValues("None", "Basic128Rsa15", "Basic256")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor CLIENT_CERT = new PropertyDescriptor
            .Builder().name("Client Certificate")
            .description("Certificate to identify the client when connecting to the UA server")
            .required(false)
            .addValidator(StandardValidators.FILE_EXISTS_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor PROTOCOL = new PropertyDescriptor
            .Builder().name("Transfer Protocol")
            .description("How should Nifi communicate with the OPC server")
            .required(true)
            .allowableValues("opc.tcp", "http")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor DEVICE = new PropertyDescriptor
            .Builder().name("Target device")
            .description("Which device to read from")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    
    public static final PropertyDescriptor CHANNEL = new PropertyDescriptor
            .Builder().name("Target channel")
            .description("Which channel to read from")
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
        descriptors.add(DEVICE);
        descriptors.add(CHANNEL);
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
    	
    	//TODO need to move the end point discovery task here

    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    	
    	final ComponentLog logger = getLogger();
    	
        FlowFile flowFile = session.get();
        if ( flowFile == null ) {
            return;
        }
        //Handle security issues
        
        //Init response variable
        final AtomicReference<String> reqTagname = new AtomicReference<>();
        final AtomicReference<String> serverResponse = new AtomicReference<>();
        
        //read tag name from flowfile input
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
        
        
        //discover endpoints
        // TODO clarify if it is necessary to discover the endpoints or if we can let the user input them as a property
 		try {
 			String url = context.getProperty(ENDPOINT).getValue();
 			endpoints = myClient.discoverEndpoints(url);	
 			
 			switch (context.getProperty(SECURITY_POLICY).getValue()) {
			
				case("None"):{
					logger.debug("The selected policy is " + context.getProperty(SECURITY_POLICY).getValue());				}
					endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.NONE);
				case("Basic128Rsa15"):{
					logger.debug("The selected policy is " + context.getProperty(SECURITY_POLICY).getValue());
					endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.NONE);
				}
				case("Basic256"):{
					logger.debug("The selected policy is " + context.getProperty(SECURITY_POLICY).getValue());
					endpoints = selectBySecurityPolicy(endpoints,SecurityPolicy.NONE);
				}
				// TODO other security policies can be added as needed 
		
 			}
 			
 			// TODO end point protocols can be added as needed
     		endpoints = selectByProtocol(endpoints, "opc.tcp");
     		
     		
 		} catch (ServiceResultException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
        
        //nodes to read string build up 
        String nodeId = "ns=" 
				+ context.getProperty(NAMESPACE).getValue()
				+ ";s="
				+ context.getProperty(CHANNEL).getValue()
				+ "."
				+ context.getProperty(DEVICE).getValue()
				+ "."
				+ reqTagname.get();
        
        ReadValueId[] NodesToRead = { 
				new ReadValueId(NodeId.parseNodeId(nodeId), Attributes.Value, null, null ),
		};
        
        //form OPC request
  		ReadRequest req = new ReadRequest();		
  		req.setMaxAge(500.00);
  		req.setTimestampsToReturn(TimestampsToReturn.Both);
  		req.setRequestHeader(null);
  		req.setNodesToRead(NodesToRead);

  		//create and activate session
  		//this needs to be maintained by a service ultimately with connection reference passed in the processor instance
  		
  		try {
  			// TODO pick a method for handling situations where more than one end point remains
  			mySession = myClient.createSessionChannel(endpoints[0]);
  			mySession.activate();
  			
  		} catch (ServiceResultException e1) {
  			// TODO Auto-generated catch block
  			e1.printStackTrace();
  		}
  					
  		//make OPC request and handle response
  		try{
          	res = mySession.Read(req);
              DataValue[] values = res.getResults();
              serverResponse.set(values[0].getValue().toString()  + ";"+ values[0].getServerTimestamp().toString() );
              
          }catch (Exception e) {
  			// TODO Auto-generated catch block
  			e.printStackTrace();
  			session.transfer(flowFile, FAILURE);
  		}
        
        // To write the results back out to flow file
        flowFile = session.write(flowFile, new OutputStreamCallback() {

            @Override
            public void process(OutputStream out) throws IOException {
            	out.write(serverResponse.get().getBytes());
            }
            
        });
        session.transfer(flowFile, SUCCESS);
        
        //close the session
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
}
