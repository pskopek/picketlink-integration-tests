/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.test.trust.tests;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Hashtable;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.ejb.EJBAccessException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

import junit.framework.Assert;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.ejb.client.ContextSelector;
import org.jboss.ejb.client.EJBClientContext;
import org.jboss.ejb.client.EJBReceiver;
import org.jboss.ejb.client.remoting.IoFutureHelper;
import org.jboss.ejb.client.remoting.RemotingConnectionEJBReceiver;
import org.jboss.logging.Logger;
import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.Remoting;
import org.jboss.remoting3.remote.RemoteConnectionProviderFactory;
import org.jboss.shrinkwrap.api.ArchivePaths;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.identity.federation.bindings.jboss.auth.SAML2STSLoginModule;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.test.integration.util.PicketLinkConfigurationUtil;
import org.picketlink.test.integration.util.PicketLinkIntegrationTests;
import org.picketlink.test.integration.util.TargetContainers;
import org.picketlink.test.trust.ejb.EchoService;
import org.picketlink.test.trust.ejb.EchoServiceImpl;
import org.w3c.dom.Element;
import org.xnio.IoFuture;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Sequence;

import com.sun.security.sasl.Provider;

/**
 * <p>
 * Tests the invocation of EJBs protected by the {@link SAML2STSLoginModule}.
 * </p>
 * 
 * TODO: Currently disabled because the SASL PLAIN mechanism is only available for JBoss AS 7.1.3+ and 7.2.0+.
 * 
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 */
@RunWith(PicketLinkIntegrationTests.class)
@RunAsClient
@TargetContainers({"jbas7", "eap6"})
public class EJBAuthorizationAS7TestCase extends TrustTestsBase {

    private static final Logger log = Logger.getLogger(EJBAuthorizationAS7TestCase.class);
    
    @Deployment(name = "ejb-test", testable = false)
    @TargetsContainer("jboss")
    public static JavaArchive createEJBTestDeployment() {
        JavaArchive archive = ShrinkWrap.create(JavaArchive.class, "ejb-test.jar");

        archive.addClass(EchoService.class);
        archive.addClass(EchoServiceImpl.class);
        archive.addAsManifestResource(new File(EJBAuthorizationAS7TestCase.class.getClassLoader()
                .getResource("jboss-deployment-structure.xml").getPath()));
        archive.addAsResource(
                new File(EJBAuthorizationAS7TestCase.class.getClassLoader().getResource("props/sts-users.properties").getPath()),
                ArchivePaths.create("users.properties"));
        archive.addAsResource(
                new File(EJBAuthorizationAS7TestCase.class.getClassLoader().getResource("props/sts-roles.properties").getPath()),
                ArchivePaths.create("roles.properties"));

        return archive;
    }

    @Deployment(name = "picketlink-sts", testable = false)
    @TargetsContainer("jboss")
    public static WebArchive createSTSDeployment() throws GeneralSecurityException, IOException {
        return TrustTestsBase.createSTSDeployment();
    }
    
    @Test
    public void testSuccessfulEJBInvocation() throws Exception {
        // add the JDK SASL Provider that allows to use the PLAIN SASL Client
        //Security.addProvider(new Provider());

        Element assertion = getAssertionFromSTS("UserA", "PassA");
        
        // JNDI environment configuration properties
        final Properties jndiProps = new Properties();
        jndiProps.setProperty(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
        jndiProps.setProperty("java.naming.provider.url", "remote://localhost:4447");
        jndiProps.setProperty("jboss.naming.client.connect.options.org.xnio.Options.SASL_POLICY_NOPLAINTEXT", "false");
        jndiProps.setProperty("javax.security.sasl.policy.noplaintext", "false");
        //jndiProps.setProperty(Context.SECURITY_PRINCIPAL, "user1");
        //jndiProps.setProperty(Context.SECURITY_CREDENTIALS, "password1");
        /*
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        
        env.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
        env.put("java.naming.factory.initial", "org.jboss.naming.remote.client.InitialContextFactory");
        env.put("java.naming.provider.url", "remote://localhost:4447");
        env.put("jboss.naming.client.ejb.context", "true");
        env.put("jboss.naming.client.connect.options.org.xnio.Options.SASL_POLICY_NOPLAINTEXT", "false");
        env.put("javax.security.sasl.policy.noplaintext", "false");
        */
        // provide the user principal and credential. The credential is the previously issued SAML assertion
        
        //env.put(Context.SECURITY_PRINCIPAL, "UserA");
        //env.put(Context.SECURITY_CREDENTIALS, DocumentUtil.getNodeAsString(assertion));
        
        // create the JNDI Context and perform the authentication using the SAML2STSLoginModule
        String assertionString = DocumentUtil.getNodeAsString(assertion);
        log.debug("assertion="+assertionString);
        
        Context context = new InitialContext(jndiProps);
        ContextSelector<EJBClientContext> old = setupEJBClientContextSelector("user1", "password1");
        String remoteJNDIContext = createRemoteEjbJndiContext("", "ejb-test", "", EchoServiceImpl.class.getSimpleName(), EchoService.class.getName(), false);
        
        // lookup the EJB
        try {
            EchoService object = (EchoService) context.lookup(remoteJNDIContext);
            // If everything is ok the Principal name will be added to the message
            Assert.assertEquals("Hi user1", object.echo("Hi "));
        }
        finally {
            safeClose((Closeable) EJBClientContext.setSelector(old));
        }
    }

    //@Test(expected = EJBAccessException.class)
    public void testNotAuthorizedEJBInvocation() throws Exception {
        // add the JDK SASL Provider that allows to use the PLAIN SASL Client
        Security.addProvider(new Provider());

        // issue a new SAML Assertion using the PicketLink STS
        Element assertion = getAssertionFromSTS("UserA", "PassA");

        // JNDI environment configuration properties
        Hashtable<String, Object> env = new Hashtable<String, Object>();

        env.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
        env.put("java.naming.factory.initial", "org.jboss.naming.remote.client.InitialContextFactory");
        env.put("java.naming.provider.url", "remote://localhost:4447");
        env.put("jboss.naming.client.ejb.context", "true");
        env.put("jboss.naming.client.connect.options.org.xnio.Options.SASL_POLICY_NOPLAINTEXT", "false");
        env.put("javax.security.sasl.policy.noplaintext", "false");

        // provide the user principal and credential. The credential is the previously issued SAML assertion
        env.put(Context.SECURITY_PRINCIPAL, "UserA");
        env.put(Context.SECURITY_CREDENTIALS, DocumentUtil.getNodeAsString(assertion));

        // create the JNDI Context and perform the authentication using the SAML2STSLoginModule
        Context context = new InitialContext(env);

        // lookup the EJB
        EchoService object = (EchoService) context.lookup("ejb-test/EchoServiceImpl!org.picketlink.test.trust.ejb.EchoService");

        // If everything is ok the Principal name will be added to the message
        Assert.assertEquals("Hi UserA", object.echoUnchecked("Hi "));
    }

    /**
     * Creates JNDI context string based on given parameters.
     * See details at https://docs.jboss.org/author/display/AS71/EJB+invocations+from+a+remote+client+using+JNDI
     *
     * @param appName - typically the ear name without the .ear
     *                - could be empty string when deploying just jar with EJBs
     * @param moduleName - jar file name without trailing .jar
     * @param distinctName - AS7 allows each deployment to have an (optional) distinct name
     *                     - could be empty string when not specified
     * @param beanName - The EJB name which by default is the simple class name of the bean implementation class
     * @param viewClassName - the remote view is fully qualified class name of @Remote EJB interface
     * @param isStateful - if the bean is stateful set to true
     *
     * @return - JNDI context string to use in your client JNDI lookup
     */
    public static String createRemoteEjbJndiContext(
            String appName,
            String moduleName,
            String distinctName,
            String beanName,
            String viewClassName,
            boolean isStateful) {

        return "ejb:" + appName + "/" + moduleName + "/" + distinctName + "/" + beanName + "!" + viewClassName
                + (isStateful ? "?stateful" : "");
    }    
    
    
    protected ContextSelector<EJBClientContext> setupEJBClientContextSelector(String username, String password) throws IOException, URISyntaxException {
        // create the endpoint
        final Endpoint endpoint = Remoting.createEndpoint("remoting-test", OptionMap.create(Options.THREAD_DAEMON, true));
        endpoint.addConnectionProvider("remote", new RemoteConnectionProviderFactory(), OptionMap.create(Options.SSL_ENABLED, false));
        final URI connectionURI = new URI("remote://localhost:4447");

        OptionMap.Builder builder = OptionMap.builder().set(Options.SASL_POLICY_NOANONYMOUS, true);
        builder.set(Options.SASL_POLICY_NOPLAINTEXT, false);
        if (password != null) {
            builder.set(Options.SASL_DISALLOWED_MECHANISMS, Sequence.of("JBOSS-LOCAL-USER"));
        } else {
            builder.set(Options.SASL_MECHANISMS, Sequence.of("JBOSS-LOCAL-USER"));
        }

        final IoFuture<Connection> futureConnection = endpoint.connect(connectionURI, builder.getMap(), new AuthenticationCallbackHandler(username, password));
        // wait for the connection to be established
        final Connection connection = IoFutureHelper.get(futureConnection, 5000, TimeUnit.MILLISECONDS);
        // create a remoting EJB receiver for this connection
        final EJBReceiver receiver = new RemotingConnectionEJBReceiver(connection);
        // associate it with the client context
        EJBClientContext context = EJBClientContext.create();
        context.registerEJBReceiver(receiver);
        return EJBClientContext.setSelector(new ClosableContextSelector(context, endpoint, connection, receiver));
    }

    private class AuthenticationCallbackHandler implements CallbackHandler {

        private final String username;
        private final String password;

        private AuthenticationCallbackHandler(final String username, final String password) {
            this.username = username == null ? "$local" : username;
            this.password = password;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

            for (Callback current : callbacks) {
                if (current instanceof RealmCallback) {
                    RealmCallback rcb = (RealmCallback) current;
                    String defaultText = rcb.getDefaultText();
                    rcb.setText(defaultText); // For now just use the realm suggested.
                } else if (current instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) current;
                    ncb.setName(username);
                } else if (current instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) current;
                    if (password != null) {
                        pcb.setPassword(password.toCharArray());
                    }
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }
        }
    }
    
    private class ClosableContextSelector implements ContextSelector<EJBClientContext>, Closeable {
        private EJBClientContext context;
        private Endpoint endpoint;
        private Connection connection;
        private EJBReceiver reciever;

        private ClosableContextSelector(EJBClientContext context, Endpoint endpoint, Connection connection, EJBReceiver receiver) {
            this.context = context;
            this.endpoint = endpoint;
            this.connection = connection;
            this.reciever = receiver;
        }

        public EJBClientContext getCurrent() {
            return context;
        }

        public void close() throws IOException {
            context.unregisterEJBReceiver(reciever);
            safeClose(connection);
            safeClose(endpoint);
            this.context = null;
        }
    }

    private void safeClose(Closeable c) {
        try {
            c.close();
        } catch (Throwable t) {
        }
    }

}