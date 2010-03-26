package org.apache.activemq.security;

import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerPlugin;

/**
 * User: Magnus Persson
 * Date: Mar 26, 2010
 * Time: 10:30:24 AM
 */
public class ManagedAuthorizationPlugin implements BrokerPlugin {

    private DynamicAuthorizationMap map;

    public ManagedAuthorizationPlugin() {
    }

    public ManagedAuthorizationPlugin(DynamicAuthorizationMap map) {
        this.map = map;
    }

    public Broker installPlugin(Broker broker) {
        if (map == null) {
            throw new IllegalArgumentException("You must configure a 'map' property");
        }
        return new ManagedAuthorizationBroker(broker, map);
    }

    public DynamicAuthorizationMap getMap() {
        return map;
    }

    public void setMap(DynamicAuthorizationMap map) {
        this.map = map;
    }

}
