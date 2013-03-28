/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
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
package org.picketlink.test.integration.security.as7;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import org.apache.commons.lang.StringUtils;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.OperationBuilder;
import org.jboss.as.network.NetworkUtils;
import org.jboss.dmr.ModelNode;
import org.jboss.logging.Logger;

/**
 * Common utilities for JBoss AS security tests.
 * 
 * @author Jan Lanik
 * @author Josef Cacek
 */
public class Utils {

    private static final Logger LOGGER = Logger.getLogger(Utils.class);

    public static void applyUpdates(final List<ModelNode> updates, final ModelControllerClient client) throws Exception {
        for (ModelNode update : updates) {
            applyUpdate(update, client);
        }
    }

    public static void applyUpdate(ModelNode update, final ModelControllerClient client) throws Exception {
        ModelNode result = client.execute(new OperationBuilder(update).build());
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Client update: " + update);
            LOGGER.info("Client update result: " + result);
        }
        if (result.hasDefined("outcome") && "success".equals(result.get("outcome").asString())) {
            LOGGER.debug("Operation succeeded.");
        } else if (result.hasDefined("failure-description")) {
            throw new RuntimeException(result.get("failure-description").toString());
        } else {
            throw new RuntimeException("Operation not successful; outcome = " + result.get("outcome"));
        }
    }

    /**
     * Returns management address (host) from the givem {@link ManagementClient}. If the returned value is IPv6 address then
     * square brackets around are stripped.
     * 
     * @param managementClient
     * @return
     */
    public static final String getHost(final ManagementClient managementClient) {
        return StringUtils.strip(managementClient.getMgmtAddress(), "[]");
    }

    /**
     * Returns cannonical hostname retrieved from management address of the givem {@link ManagementClient}.
     * 
     * @param managementClient
     * @return
     */
    public static final String getCannonicalHost(final ManagementClient managementClient) {
        return getCannonicalHost(managementClient.getMgmtAddress());
    }

    /**
     * Returns cannonical hostname form of the given address.
     * 
     * @param address hosname or IP address
     * @return
     */
    public static final String getCannonicalHost(final String address) {
        String host = StringUtils.strip(address, "[]");
        try {
            host = InetAddress.getByName(host).getCanonicalHostName();
        } catch (UnknownHostException e) {
            LOGGER.warn("Unable to get cannonical host name", e);
        }
        return host.toLowerCase(Locale.ENGLISH);
    }

    /**
     * Returns given URI with the replaced hostname. If the URI or host is null, then the original URI is returned.
     * 
     * @param uri
     * @param host
     * @return
     * @throws URISyntaxException
     */
    public static final URI replaceHost(final URI uri, final String host) throws URISyntaxException {
        final String origHost = uri == null ? null : uri.getHost();
        final String newHost = NetworkUtils.formatPossibleIpv6Address(host);
        if (origHost == null || newHost == null || newHost.equals(origHost)) {
            return uri;
        }
        return new URI(uri.toString().replace(origHost, newHost));
    }

    /**
     * Returns servlet URL, as concatenation of webapp URL and servlet path.
     * 
     * @param webAppURL web application context URL (e.g. injected by Arquillian)
     * @param servletPath Servlet path starting with slash (must be not-<code>null</code>)
     * @param mgmtClient Management Client (may be null)
     * @param useCannonicalHost flag which says if host in URI should be replaced by the cannonical host.
     * @return
     * @throws URISyntaxException
     */
    public static final URI getServletURI(final URL webAppURL, final String servletPath, final ManagementClient mgmtClient,
            boolean useCannonicalHost) throws URISyntaxException {
        URI resultURI = new URI(webAppURL.toExternalForm() + servletPath.substring(1));
        if (useCannonicalHost) {
            resultURI = replaceHost(resultURI, getCannonicalHost(mgmtClient));
        }
        return resultURI;
    }

}
