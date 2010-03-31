A perhaps not perfect nor efficient ActiveMQ plugin for managing
destination authorization over JMX. It can (should) act as a
replacement for AuthorizationBroker(/plugin) that is included
with the base distribution of ActiveMQ.

Of notable mention is that the plugin post-processes the
initial authorizationmap and breaks up composite destinations.
That is, if there is

    <authorizationMap xmlns="http://activemq.apache.org/schema/core">
        <authorizationEntries>
            ...
            <authorizationEntry queue="composite.one,composite.two" .../>
            ...
        </authorizationEntries>
    </authorizationMap>

It will in effect be reparsed as

    <map>
        <authorizationMap xmlns="http://activemq.apache.org/schema/core">
            <authorizationEntries>
                ...
                <authorizationEntry queue="composite.one" .../>
                <authorizationEntry queue="composite.two" .../>
                ...
            </authorizationEntries>
        </authorizationMap>
    </map>

When invoking the mbean you should also only specify one operation and
role. I.e. dont invoke as "read,write" for operation, rather invoke the
mbean twice for each operation. If invoked with a composite destination
it will similar to above be broken apart.

Temporary destinations cannot currently be managed - they work as per
default.

## Example broker configuration

    <beans
        xmlns="http://www.springframework.org/schema/beans"
        xmlns:amq="http://activemq.apache.org/schema/core"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-2.0.xsd
        http://activemq.apache.org/schema/core http://activemq.apache.org/schema/core/activemq-core.xsd">

    <amq:broker useJmx="true" persistent="false">
        <amq:plugins>
            <simpleAuthenticationPlugin xmlns="http://activemq.apache.org/schema/core">
                <users>
                    <authenticationUser username="admin" password="admin" groups="users,admins"/>
                    <authenticationUser username="user" password="user" groups="users"/>
                    <authenticationUser username="guest" password="guest" groups="guests"/>
                </users>
            </simpleAuthenticationPlugin>
            <ManagedAuthorizationPlugin xmlns="java://org.apache.activemq.security">
                <map>
                    <authorizationMap xmlns="http://activemq.apache.org/schema/core">
                        <authorizationEntries>
                            <authorizationEntry queue=">" read="admins" write="admins" admin="admins"/>
                            <authorizationEntry topic=">" read="admins" write="admins" admin="admins"/>
                            <authorizationEntry topic="ActiveMQ.Advisory.>" read="guests,users" write="guests,users"
                                                admin="guests,users"/>
                        </authorizationEntries>
                        <tempDestinationAuthorizationEntry>
                            <tempDestinationAuthorizationEntry read="tempDestinationAdmins"
                                                               write="tempDestinationAdmins"
                                                               admin="tempDestinationAdmins"/>
                        </tempDestinationAuthorizationEntry>
                    </authorizationMap>
                </map>
            </ManagedAuthorizationPlugin>
        </amq:plugins>
        <amq:transportConnectors>
            <amq:transportConnector uri="tcp://0.0.0.0:61616"/>
            <amq:transportConnector uri="stomp://0.0.0.0:61613"/>
        </amq:transportConnectors>
    </amq:broker>
