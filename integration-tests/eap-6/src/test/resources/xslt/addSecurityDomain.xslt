<?xml version="1.0" encoding="UTF-8"?>
<!-- XSLT file to add the security domains to the standalone.xml used during the integration tests. -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                xmlns:as="urn:jboss:domain:1.4" 
                xmlns:sd="urn:jboss:domain:security:1.2" 
                xmlns:r="urn:jboss:domain:remoting:1.1" 
                version="1.0">

  <xsl:output method="xml" indent="yes" />

  <xsl:template match="as:profile/r:subsystem/r:connector">
      <connector name="remoting-connector" socket-binding="remoting" security-realm="SAMLRealm"/>
  </xsl:template>
  

  <xsl:template match="as:management/as:security-realms">
      <security-realms>
        <xsl:apply-templates select="@* | *" />   
        <security-realm name="SAMLRealm">
          <authentication>
            <jaas name="ejb-remoting-sts"/>
          </authentication>
        </security-realm>
      </security-realms>        
  </xsl:template>

  <xsl:template match="as:profile/sd:subsystem/sd:security-domains">
    <security-domains>
      <security-domain name="idp" cache-type="default">
        <authentication>
          <login-module code="UsersRoles" flag="required">
            <module-option name="usersProperties" value="users.properties" />
            <module-option name="rolesProperties" value="roles.properties" />
          </login-module>
        </authentication>
      </security-domain>
      <security-domain name="picketlink-sts" cache-type="default">
        <authentication>
          <login-module code="UsersRoles" flag="required">
            <module-option name="usersProperties" value="users.properties" />
            <module-option name="rolesProperties" value="roles.properties" />
          </login-module>
        </authentication>
      </security-domain>
      <security-domain name="sp" cache-type="default">
        <authentication>
          <login-module code="org.picketlink.identity.federation.bindings.jboss.auth.SAML2LoginModule" flag="required" />
        </authentication>
      </security-domain>
      <security-domain name="authenticator" cache-type="default">
        <authentication>
          <login-module code="org.picketlink.test.trust.loginmodules.TestRequestUserLoginModule" flag="required">
            <module-option name="usersProperties" value="users.properties" />
            <module-option name="rolesProperties" value="roles.properties" />
          </login-module>
        </authentication>
      </security-domain>
      <security-domain name="sts" cache-type="default">
        <authentication>
          <login-module code="org.picketlink.identity.federation.bindings.jboss.auth.SAML2STSLoginModule" flag="required">
            <module-option name="configFile" value="sts-config.properties" />
            <module-option name="password-stacking" value="useFirstPass" />
          </login-module>
          <login-module code="UsersRoles" flag="required">
            <module-option name="usersProperties" value="users.properties" />
            <module-option name="rolesProperties" value="roles.properties" />
            <module-option name="password-stacking" value="useFirstPass" />
          </login-module>
        </authentication>
      </security-domain>
      <security-domain name="localValidationDomain">
        <xsl:element name="jsse">
          <xsl:attribute name="keystore-url">file:///${jboss.server.config.dir}/stspub.jks</xsl:attribute>
          <xsl:attribute name="keystore-password">keypass</xsl:attribute>
          <xsl:attribute name="keystore-type">JKS</xsl:attribute>
          <xsl:attribute name="server-alias">sts</xsl:attribute>
        </xsl:element>
      </security-domain>
      <security-domain name="gateway" cache-type="default">
        <authentication>
          <!-- dummy login module for test purposes -->
          <login-module code="org.picketlink.test.trust.loginmodules.TokenSupplierTestLoginModule" flag="required">
            <module-option name="map.token.key" value="ClientID" />
            <module-option name="ClientID" value="test-token-value:g2s-http" />
            <module-option name="password-stacking" value="useFirstPass" />
          </login-module>
          <!-- this LM will pick ClientID value supplied by previous LM and construct specific ws-trust request to ge tsecurity token -->
          <login-module code="org.picketlink.trust.jbossws.jaas.JBWSTokenIssuingLoginModule" flag="required">
            <module-option name="endpointAddress" value="http://localhost:8080/picketlink-sts/PicketLinkSTS" />
            <module-option name="serviceName" value="PicketLinkSTS" />
            <module-option name="portName" value="PicketLinkSTSPort" />
            <module-option name="inject.callerprincipal" value="true" />
            <module-option name="map.token.key" value="ClientID" />
            <!-- use default value module-option name="requestType">http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate</module-option -->
            <module-option name="soapBinding" value="http://www.w3.org/2003/05/soap/bindings/HTTP/" />
            <module-option name="isBatch" value="false" />

            <module-option name="wspAppliesTo" value="http://services.testcorp.org/provider1" />
            <module-option name="wsaIssuer" value="http://services.testcorp.org/provider1" />
            <module-option name="roleKey" value="Membership" />

            <module-option name="username" value="UserA" />
            <module-option name="password" value="PassA" />
          </login-module>
          <login-module code="org.picketlink.trust.jbossws.jaas.SAMLRoleLoginModule" flag="required" />
        </authentication>
      </security-domain>
      <security-domain name="service" cache-type="default">
        <authentication>
          <login-module code="org.picketlink.identity.federation.bindings.jboss.auth.SAML2STSLoginModule" flag="required">
            <module-option name="password-stacking" value="useFirstPass" />
            <module-option name="cache.invalidation" value="true" />
            <module-option name="localValidation" value="true" />
            <module-option name="localValidationSecurityDomain" value="localValidationDomain" />
            <module-option name="tokenEncodingType" value="gzip" />
            <module-option name="samlTokenHttpHeader" value="Auth" />
            <module-option name="samlTokenHttpHeaderRegEx" value=".*&quot;(.*)&quot;.*" />
            <module-option name="samlTokenHttpHeaderRegExGroup" value="1" />
          </login-module>
          <login-module code="org.picketlink.trust.jbossws.jaas.SAMLRoleLoginModule" flag="required" />
        </authentication>
        <xsl:element name="jsse">
          <xsl:attribute name="keystore-url">file:///${jboss.server.config.dir}/stspub.jks</xsl:attribute>
          <xsl:attribute name="keystore-password">keypass</xsl:attribute>
          <xsl:attribute name="keystore-type">JKS</xsl:attribute>
          <xsl:attribute name="server-alias">sts</xsl:attribute>
        </xsl:element>
      </security-domain>
      <security-domain name="ejb-remoting-sts" cache-type="default">
         <authentication>
              <login-module code="org.picketlink.identity.federation.bindings.jboss.auth.SAML2STSLoginModule" flag="required" module="org.picketlink">
                 <module-option name="password-stacking" value="useFirstPass"/>
                 <xsl:element name="module-option">
                  <xsl:attribute name="name">configFile</xsl:attribute>
                  <xsl:attribute name="value">${jboss.server.config.dir}/sts-config.properties</xsl:attribute>
                 </xsl:element>
              </login-module>
              <login-module code="UsersRoles" flag="required">
                 <module-option name="password-stacking" value="useFirstPass"/>
                 <xsl:element name="module-option">
                  <xsl:attribute name="name">usersProperties</xsl:attribute>
                  <xsl:attribute name="value">${jboss.server.config.dir}/ejb-sts-users.properties</xsl:attribute>
                 </xsl:element>
                 <xsl:element name="module-option">
                  <xsl:attribute name="name">rolesProperties</xsl:attribute>
                  <xsl:attribute name="value">${jboss.server.config.dir}/ejb-sts-roles.properties</xsl:attribute>
                 </xsl:element>
              </login-module>              
         </authentication>
      </security-domain>

      <xsl:apply-templates select="@* | *" />
    </security-domains>
  </xsl:template>

  <!-- Copy everything else. -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()" />
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>