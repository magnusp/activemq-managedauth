package org.apache.activemq.security;

import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerFilter;
import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.broker.ProducerBrokerExchange;
import org.apache.activemq.broker.jmx.ManagementContext;
import org.apache.activemq.broker.region.Destination;
import org.apache.activemq.broker.region.Subscription;
import org.apache.activemq.command.*;
import org.apache.activemq.jaas.GroupPrincipal;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.management.ObjectName;
import javax.management.StandardMBean;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * User: Magnus Persson
 * Date: Mar 26, 2010
 * Time: 10:07:46 AM
 */
public class ManagedAuthorizationBroker extends BrokerFilter implements InspectableSecurityAdminMBean {
    private static Log log = LogFactory.getLog(ManagedAuthorizationBroker.class);
    private final DynamicAuthorizationMap authorizationMap;

    public ManagedAuthorizationBroker(Broker next, DynamicAuthorizationMap authorizationMap) {
        super(next);
        this.authorizationMap = authorizationMap;
    }

    public Destination addDestination(ConnectionContext context, ActiveMQDestination destination) throws Exception {
        final SecurityContext securityContext = (SecurityContext) context.getSecurityContext();
        if (securityContext == null) {
            throw new SecurityException("User is not authenticated.");
        }

        Destination existing = this.getDestinationMap().get(destination);
        if (existing != null) {
            return super.addDestination(context, destination);
        }

        if (!securityContext.isBrokerContext()) {
            Set<?> allowedACLs = null;
            if (!destination.isTemporary()) {
                allowedACLs = authorizationMap.getAdminACLs(destination);
            } else {
                allowedACLs = authorizationMap.getTempDestinationAdminACLs();
            }

            if (allowedACLs != null && !securityContext.isInOneOf(allowedACLs)) {
                throw new SecurityException("User " + securityContext.getUserName() + " is not authorized to create: " + destination);
            }

        }

        return super.addDestination(context, destination);
    }

    public void removeDestination(ConnectionContext context, ActiveMQDestination destination, long timeout) throws Exception {

        final SecurityContext securityContext = (SecurityContext) context.getSecurityContext();
        if (securityContext == null) {
            throw new SecurityException("User is not authenticated.");
        }
        Set<?> allowedACLs = null;
        if (!destination.isTemporary()) {
            allowedACLs = authorizationMap.getAdminACLs(destination);
        } else {
            allowedACLs = authorizationMap.getTempDestinationAdminACLs();
        }

        if (!securityContext.isBrokerContext() && allowedACLs != null && !securityContext.isInOneOf(allowedACLs)) {
            throw new SecurityException("User " + securityContext.getUserName() + " is not authorized to remove: " + destination);
        }
        super.removeDestination(context, destination, timeout);
    }

    public Subscription addConsumer(ConnectionContext context, ConsumerInfo info) throws Exception {

        final SecurityContext subject = (SecurityContext) context.getSecurityContext();
        if (subject == null) {
            throw new SecurityException("User is not authenticated.");
        }
        Set<?> allowedACLs = null;
        if (!info.getDestination().isTemporary()) {
            allowedACLs = authorizationMap.getReadACLs(info.getDestination());
        } else {
            allowedACLs = authorizationMap.getTempDestinationReadACLs();
        }

        if (!subject.isBrokerContext() && allowedACLs != null && !subject.isInOneOf(allowedACLs)) {
            throw new SecurityException("User " + subject.getUserName() + " is not authorized to read from: " + info.getDestination());
        }
        subject.getAuthorizedReadDests().put(info.getDestination(), info.getDestination());

        /*
         * Need to think about this a little more. We could do per message
         * security checking to implement finer grained security checking. For
         * example a user can only see messages with price>1000 . Perhaps this
         * should just be another additional broker filter that installs this
         * type of feature. If we did want to do that, then we would install a
         * predicate. We should be careful since there may be an existing
         * predicate already assigned and the consumer info may be sent to a
         * remote broker, so it also needs to support being marshaled.
         * info.setAdditionalPredicate(new BooleanExpression() { public boolean
         * matches(MessageEvaluationContext message) throws JMSException { if(
         * !subject.getAuthorizedReadDests().contains(message.getDestination()) ) {
         * Set allowedACLs =
         * authorizationMap.getReadACLs(message.getDestination());
         * if(allowedACLs!=null && !subject.isInOneOf(allowedACLs)) return
         * false; subject.getAuthorizedReadDests().put(message.getDestination(),
         * message.getDestination()); } return true; } public Object
         * evaluate(MessageEvaluationContext message) throws JMSException {
         * return matches(message) ? Boolean.TRUE : Boolean.FALSE; } });
         */

        return super.addConsumer(context, info);
    }

    public void addProducer(ConnectionContext context, ProducerInfo info) throws Exception {

        SecurityContext subject = (SecurityContext) context.getSecurityContext();
        if (subject == null) {
            throw new SecurityException("User is not authenticated.");
        }
        if (!subject.isBrokerContext() && info.getDestination() != null) {

            Set<?> allowedACLs = null;
            if (!info.getDestination().isTemporary()) {
                allowedACLs = authorizationMap.getWriteACLs(info.getDestination());
            } else {
                allowedACLs = authorizationMap.getTempDestinationWriteACLs();
            }
            if (allowedACLs != null && !subject.isInOneOf(allowedACLs)) {
                throw new SecurityException("User " + subject.getUserName() + " is not authorized to write to: " + info.getDestination());
            }
            subject.getAuthorizedWriteDests().put(info.getDestination(), info.getDestination());
        }

        super.addProducer(context, info);
    }

    public void send(ProducerBrokerExchange producerExchange, Message messageSend) throws Exception {
        SecurityContext subject = (SecurityContext) producerExchange.getConnectionContext().getSecurityContext();
        if (subject == null) {
            throw new SecurityException("User is not authenticated.");
        }
        if (!subject.isBrokerContext() && !subject.getAuthorizedWriteDests().contains(messageSend.getDestination())) {

            Set<?> allowedACLs = null;
            if (!messageSend.getDestination().isTemporary()) {
                allowedACLs = authorizationMap.getWriteACLs(messageSend.getDestination());
            } else {
                allowedACLs = authorizationMap.getTempDestinationWriteACLs();
            }

            if (allowedACLs != null && !subject.isInOneOf(allowedACLs)) {
                throw new SecurityException("User " + subject.getUserName() + " is not authorized to write to: " + messageSend.getDestination());
            }
            subject.getAuthorizedWriteDests().put(messageSend.getDestination(), messageSend.getDestination());
        }

        super.send(producerExchange, messageSend);
    }

    // SecurityAdminMBean interface
    // -------------------------------------------------------------------------

    // Noop

    public void addRole(String role) {
    }

    // Noop

    public void addUserRole(String user, String role) {
    }

    // Noop

    public void removeRole(String role) {
    }

    // Noop

    public void removeUserRole(String user, String role) {
    }

    public void addDestinationRole(ActiveMQDestination destination, String operation, String role) throws Exception {
        for (AuthorizationEntry ae : authorizationMap.getAllEntries(destination)) {
            GroupPrincipal newPrincipal = new GroupPrincipal(role);

            if (ae.getDestination().isPattern()) {
                if (operation.equals("read") && ae.getReadACLs().contains(newPrincipal)) {
                    return;
                } else if (operation.equals("write") && ae.getWriteACLs().contains(newPrincipal)) {
                    return;
                } else if (operation.equals("admin") && ae.getAdminACLs().contains(newPrincipal)) {
                    return;
                }
            }

            if (!ae.getDestination().equals(destination))
                continue;

            if (operation.equals("read")) {
                if (!ae.getReadACLs().contains(newPrincipal)) {
                    if (ae.getReadACLs().equals(Collections.EMPTY_SET)) {
                        ae.setReadACLs(new HashSet<Object>());
                    }
                    ae.getReadACLs().add(newPrincipal);
                }
            } else if (operation.equals("write")) {
                if (!ae.getWriteACLs().contains(newPrincipal)) {
                    if (ae.getWriteACLs().equals(Collections.EMPTY_SET)) {
                        ae.setWriteACLs(new HashSet<Object>());
                    }
                    ae.getWriteACLs().add(newPrincipal);
                }
            } else if (operation.equals("admin")) {
                if (!ae.getAdminACLs().contains(newPrincipal)) {
                    if (ae.getAdminACLs().equals(Collections.EMPTY_SET)) {
                        ae.setAdminACLs(new HashSet<Object>());
                    }
                    ae.getAdminACLs().add(newPrincipal);
                }
            }
            return;
        }

        AuthorizationEntry ae = new AuthorizationEntry();
        ae.setDestination(destination);
        if (operation.equals("read")) {
            ae.setRead(role);
        } else if (operation.equals("write")) {
            ae.setWrite(role);
        } else if (operation.equals("admin")) {
            ae.setAdmin(role);
        }
        authorizationMap.put(destination, ae);
    }

    public void addTopicRole(String topic, String operation, String role) {
        log.debug("topic://" + topic + " - ADD " + operation + " :: " + role);
        try {
            addDestinationRole(new ActiveMQTopic(topic), operation, role);
        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    public void addQueueRole(String queue, String operation, String role) {
        log.debug("queue://" + queue + " - ADD " + operation + " :: " + role);
        try {
            addDestinationRole(new ActiveMQQueue(queue), operation, role);
        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    public void removeDestinationRole(ActiveMQDestination destination, String operation, String role) {
        GroupPrincipal oldPrincipal = new GroupPrincipal(role);

        Set<AuthorizationEntry> entries = authorizationMap.getAllEntries(destination);
        for (AuthorizationEntry ae : entries) {
            if (operation.equals("read")) {
                if (ae.getReadACLs().equals(Collections.EMPTY_SET))
                    return;

                ae.getReadACLs().remove(oldPrincipal);
            } else if (operation.equals("write")) {
                if (ae.getWriteACLs().equals(Collections.EMPTY_SET))
                    return;

                ae.getWriteACLs().remove(oldPrincipal);
            } else if (operation.equals("read")) {
                if (ae.getAdminACLs().equals(Collections.EMPTY_SET))
                    return;

                ae.getAdminACLs().remove(oldPrincipal);
            } else
                return;

            if (ae.getReadACLs().size() + ae.getWriteACLs().size() + ae.getAdminACLs().size() == 0) {
                authorizationMap.remove(destination, ae);
            }
        }
    }

    public void removeQueueRole(String queue, String operation, String role) {
        removeDestinationRole(new ActiveMQQueue(queue), operation, role);
    }

    public void removeTopicRole(String topic, String operation, String role) {
        removeDestinationRole(new ActiveMQTopic(topic), operation, role);
    }

    public void start() throws Exception {
        super.start();
        ManagementContext mc = getBrokerService().getManagementContext();
        StringBuilder sb = new StringBuilder();
        sb.append(mc.getJmxDomainName());
        sb.append(":BrokerName=").append(getBrokerName());
        sb.append(",Type=ManagedAuthorizationBroker");
        ObjectName name = new ObjectName(sb.toString());

        mc.registerMBean(new StandardMBean(this, InspectableSecurityAdminMBean.class), name);
    }

    public void logAuthorizations() {
        Set<AuthorizationEntry> entries = new HashSet<AuthorizationEntry>();
        entries.addAll(authorizationMap.getAllEntries(new ActiveMQTopic(">")));
        entries.addAll(authorizationMap.getAllEntries(new ActiveMQQueue(">")));

        for (AuthorizationEntry ae : entries) {
            StringBuilder sb = new StringBuilder("");
            sb.append(ae.getDestination().toString());
            sb.append(" :: r[");
            for (Object acl : ae.getReadACLs()) {
                sb.append(" ");
                sb.append(((Principal) acl).getName());
            }
            sb.append(" ] w[");
            for (Object acl : ae.getWriteACLs()) {
                sb.append(" ");
                sb.append(((Principal) acl).getName());
            }
            sb.append(" ] a[");
            for (Object acl : ae.getAdminACLs()) {
                sb.append(" ");
                sb.append(((Principal) acl).getName());
            }
            sb.append(" ]");
            log.debug(sb.toString());
        }
    }
}
