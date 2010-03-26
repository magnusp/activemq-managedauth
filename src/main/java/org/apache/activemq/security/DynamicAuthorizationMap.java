package org.apache.activemq.security;

import org.apache.activemq.command.ActiveMQTopic;

import java.util.ArrayList;
import java.util.List;

/**
 * User: Magnus Persson
 * Date: Mar 24, 2010
 * Time: 1:29:06 PM
 */
public class DynamicAuthorizationMap extends DefaultAuthorizationMap {
    public DynamicAuthorizationMap() throws Exception {
        super();
        AuthorizationEntry ae = new AuthorizationEntry();
        ae.setDestination(new ActiveMQTopic("ActiveMQ.Advisory.>"));
        ae.setRead("users,admins,guests");
        ae.setWrite("users,admins,guests");
        ae.setAdmin("users,admins,guests");
        List<AuthorizationEntry> l = new ArrayList<AuthorizationEntry>();
        l.add(ae);
        setEntries(l);
    }
}
