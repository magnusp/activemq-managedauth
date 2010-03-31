package org.apache.activemq.security;

/**
 * User: Magnus Persson
 * Date: Mar 26, 2010
 * Time: 11:35:53 AM
 */
public interface InspectableSecurityAdminMBean extends SecurityAdminMBean {
    String[] inspect();
}
