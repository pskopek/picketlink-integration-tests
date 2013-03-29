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
import java.util.Collection;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.runner.RunWith;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.test.integration.util.MavenArtifactUtil;
import org.picketlink.test.integration.util.PicketLinkConfigurationUtil;
import org.picketlink.test.integration.util.PicketLinkIntegrationTests;
import org.picketlink.test.integration.util.TargetContainers;
import org.picketlink.test.trust.loginmodules.TokenSupplierTestLoginModule;
import org.picketlink.test.trust.servlet.GatewayServlet;
import org.picketlink.test.trust.servlet.ServiceServlet;

/**
 * Unit test to test scenario with JBWSTokenIssuingLoginModule as gateway which obtains SAML token 
 * and stores it in to the JAAS subject. It is later picked by GatewayServlet app and passed
 * in http request as header to another app (service) which will use SAML2STSLoginModule to get
 * the SAML token and locally validate it and grant access to the service app. 
 *
 * @author Peter Skopek: pskopek at redhat dot com
 * @since Aug 29, 2012
 */

@ServerSetup({})
@RunWith(PicketLinkIntegrationTests.class)
@TargetContainers({"jbas7","eap6"})
public class Gateway2ServiceHttpUnitAS7TestCase extends Gateway2ServiceHttpUnitCommon {

    protected static final Logger log = Logger.getLogger(Gateway2ServiceHttpUnitAS7TestCase.class);

    // for actuall tests see Gateway2ServiceHttpUnitCommon class
    
/*
    @Deployment(name = "g2s-http-sec-domains.jar", testable = false, order = 2)
    @TargetsContainer("jboss")
    public static JavaArchive deployTestScenario1() throws IOException {
        JavaArchive ts = ShrinkWrap.create(JavaArchive.class, "g2s-http-sec-domains.jar");
        ts.addClass(TokenSupplierTestLoginModule.class);
        ts.addAsManifestResource(new File("../../unit-tests/trust/target/test-classes/lmtestapp/gateway2service-http/jboss-beans.xml"));
        //ts.as(ZipExporter.class).exportTo(new File(ts.getName()), true);
        return ts;
    }
*/
    @Deployment(name = "gateway.war", testable = false, order = 4)
    @TargetsContainer("jboss")
    public static WebArchive deployGatewayApp() throws IOException { 
        
        Collection<JavaArchive> httpClientDeps = MavenArtifactUtil.getArtifact("org.apache.httpcomponents:httpclient:jar:4.2.1");
        
        WebArchive war = ShrinkWrap.create(WebArchive.class, "gateway.war");
        war.addClass(GatewayServlet.class);
        war.addClass(TokenSupplierTestLoginModule.class);
        war.addAsLibraries(httpClientDeps);
        war.addAsWebInfResource(new File("../../unit-tests/trust/target/test-classes/lmtestapp/gateway2service-http/gateway/jboss-web.xml"));
        war.addAsWebInfResource(new File("../../unit-tests/trust/target/test-classes/lmtestapp/gateway2service-http/gateway/web.xml"));
        war.addAsManifestResource(new File("../../unit-tests/trust/target/test-classes/jboss-deployment-structure.xml"));
        //war.as(ZipExporter.class).exportTo(new File(war.getName()), true);
        return war;
    }

    @Deployment(name = "service.war", testable = false, order = 5)
    @TargetsContainer("jboss")
    public static WebArchive deployServiceApp() throws IOException {
        WebArchive war = ShrinkWrap.create(WebArchive.class, "service.war");
        war.addClass(ServiceServlet.class);
        war.addAsWebInfResource(new File("../../unit-tests/trust/target/test-classes/lmtestapp/gateway2service-http/service/as7/jboss-web.xml"));
        war.addAsWebInfResource(new File("../../unit-tests/trust/target/test-classes/lmtestapp/gateway2service-http/service/web.xml"));
        war.addAsWebInfResource(new File("../../unit-tests/trust/target/test-classes/lmtestapp/gateway2service-http/service/context.xml"));
        war.addAsManifestResource(new File("../../unit-tests/trust/target/test-classes/jboss-deployment-structure.xml"));
        //war.as(ZipExporter.class).exportTo(new File(war.getName()), true);
        return war;
    }

    // just to override
    public static JavaArchive createWSTestDeployment() throws ConfigurationException, ProcessingException, ParsingException,
            InterruptedException {
        return null;
    }

    @Deployment(name = "picketlink-sts", testable = false)
    @TargetsContainer("jboss")
    public static WebArchive createSTSDeployment() throws GeneralSecurityException, IOException {
        WebArchive sts = TrustTestsBase.createSTSDeployment();
        PicketLinkConfigurationUtil.addSAML20TokenRoleAttributeProvider(sts, "/WEB-INF/classes/picketlink-sts.xml", "Role");
        //sts.as(ZipExporter.class).exportTo(new File("picketlink-sts.war"), true);
        return sts;
    }

}