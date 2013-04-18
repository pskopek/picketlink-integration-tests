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

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Properties;

import javax.ejb.EJBAccessException;
import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.Assert;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ArchivePaths;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.identity.federation.bindings.jboss.auth.SAML2STSLoginModule;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.test.integration.util.PicketLinkIntegrationTests;
import org.picketlink.test.integration.util.TargetContainers;
import org.picketlink.test.trust.ejb.EchoService;
import org.picketlink.test.trust.ejb.EchoServiceImpl;
import org.w3c.dom.Element;
import com.sun.security.sasl.Provider;

/**
 * <p>
 * Tests the invocation of EJBs protected by the {@link SAML2STSLoginModule}.
 * </p>
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
        /*
        archive.addAsResource(
                new File(EJBAuthorizationAS7TestCase.class.getClassLoader().getResource("props/sts-users.properties").getPath()),
                ArchivePaths.create("users.properties"));
        archive.addAsResource(
                new File(EJBAuthorizationAS7TestCase.class.getClassLoader().getResource("props/sts-roles.properties").getPath()),
                ArchivePaths.create("roles.properties"));
    */
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
        Security.addProvider(new Provider());

        Element assertion = getAssertionFromSTS("UserA", "PassA");

        // JNDI environment configuration properties
        final Properties jndiProps = new Properties();
        jndiProps.setProperty(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
        jndiProps.setProperty("java.naming.factory.initial", "org.jboss.naming.remote.client.InitialContextFactory");
        jndiProps.setProperty("java.naming.provider.url", "remote://localhost:4447");
        jndiProps.setProperty("jboss.naming.client.ejb.context", "true");
        jndiProps.setProperty("jboss.naming.client.connect.options.org.xnio.Options.SASL_POLICY_NOPLAINTEXT", "false");
        jndiProps.setProperty("javax.security.sasl.policy.noplaintext", "false");


        String assertionString = DocumentUtil.getNodeAsString(assertion);

        jndiProps.setProperty(Context.SECURITY_PRINCIPAL, "UserA");
        jndiProps.setProperty(Context.SECURITY_CREDENTIALS, assertionString);

        // create the JNDI Context and perform the authentication using the SAML2STSLoginModule
        Context context = new InitialContext(jndiProps);

     //   String remoteJNDIContext = createRemoteEjbJndiContext("", "ejb-test", "", EchoServiceImpl.class.getSimpleName(), EchoService.class.getName(), false);
        String remoteJNDIContext = "ejb-test//EchoServiceImpl!org.picketlink.test.trust.ejb.EchoService";
        log.debug("remoteJNDIContext="+remoteJNDIContext);
        // lookup the EJB
        EchoService object = (EchoService) context.lookup(remoteJNDIContext);
        // If everything is ok the Principal name will be added to the message
        Assert.assertEquals("Hi UserA", object.echo("Hi "));
    }

    @Test(expected = EJBAccessException.class)
    public void testNotAuthorizedEJBInvocation() throws Exception {
        // add the JDK SASL Provider that allows to use the PLAIN SASL Client
        Security.addProvider(new Provider());

        // issue a new SAML Assertion using the PicketLink STS
        Element assertion = getAssertionFromSTS("UserA", "PassA");

        // JNDI environment configuration properties
        final Properties jndiProps = new Properties();
        jndiProps.setProperty(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
        jndiProps.setProperty("java.naming.factory.initial", "org.jboss.naming.remote.client.InitialContextFactory");
        jndiProps.setProperty("java.naming.provider.url", "remote://localhost:4447");
        jndiProps.setProperty("jboss.naming.client.ejb.context", "true");
        jndiProps.setProperty("jboss.naming.client.connect.options.org.xnio.Options.SASL_POLICY_NOPLAINTEXT", "false");
        jndiProps.setProperty("javax.security.sasl.policy.noplaintext", "false");

        String assertionString = DocumentUtil.getNodeAsString(assertion);
        
        // provide the user principal and credential. The credential is the previously issued SAML assertion
        jndiProps.setProperty(Context.SECURITY_PRINCIPAL, "UserA");
        jndiProps.setProperty(Context.SECURITY_CREDENTIALS, assertionString);

        // create the JNDI Context and perform the authentication using the SAML2STSLoginModule
        Context context = new InitialContext(jndiProps);

     //   String remoteJNDIContext = createRemoteEjbJndiContext("", "ejb-test", "", EchoServiceImpl.class.getSimpleName(), EchoService.class.getName(), false);
        String remoteJNDIContext = "ejb-test//EchoServiceImpl!org.picketlink.test.trust.ejb.EchoService";

        log.debug("remoteJNDIContext="+remoteJNDIContext);
        // lookup the EJB
        EchoService object = (EchoService) context.lookup(remoteJNDIContext);

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

}