package org.apache.activemq.security;

import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerPlugin;

/**
 * User: Magnus Persson
 * Date: Mar 26, 2010
 * Time: 10:30:24 AM
 */
public class ManagedAuthorizationPlugin implements BrokerPlugin {

    private DefaultAuthorizationMap map;

    public ManagedAuthorizationPlugin() {
    }

    public ManagedAuthorizationPlugin(DefaultAuthorizationMap map) {
        this.map = map;
    }

    public Broker installPlugin(Broker broker) {
        if (map == null) {
            throw new IllegalArgumentException("You must configure a 'map' property");
        }
        return new ManagedAuthorizationBroker(broker, map);
    }

    public DefaultAuthorizationMap getMap() {
        return map;
    }

    public void setMap(DefaultAuthorizationMap map) {
        this.map = map;
    }

}
