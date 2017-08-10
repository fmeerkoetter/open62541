/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include "ua_config_standard.h"
#include "ua_log_stdout.h"
#include "ua_network_tcp.h"
#include "ua_accesscontrol_default.h"
#include "ua_types_generated.h"
#include "ua_types.h"

#define ANONYMOUS_POLICY "open62541-anonymous-policy"
#define USERNAME_POLICY "open62541-username-policy"

 /*******************************/
 /* Default Connection Settings */
 /*******************************/

const UA_ConnectionConfig UA_ConnectionConfig_default = {
    0, /* .protocolVersion */
    65535, /* .sendBufferSize, 64k per chunk */
    65535, /* .recvBufferSize, 64k per chunk */
    0, /* .maxMessageSize, 0 -> unlimited */
    0 /* .maxChunkCount, 0 -> unlimited */
};

/***************************/
/* Default Server Settings */
/***************************/

#define MANUFACTURER_NAME "open62541"
#define PRODUCT_NAME "open62541 OPC UA Server"
#define PRODUCT_URI "http://open62541.org"
#define APPLICATION_NAME "open62541-based OPC UA Application"
#define APPLICATION_URI "urn:unconfigured:application"

#define UA_STRING_STATIC(s) {sizeof(s)-1, (UA_Byte*)s}
#define UA_STRING_STATIC_NULL {0, NULL}
#define STRINGIFY(arg) #arg
#define VERSION(MAJOR, MINOR, PATCH, LABEL) \
    STRINGIFY(MAJOR) "." STRINGIFY(MINOR) "." STRINGIFY(PATCH) LABEL

static UA_StatusCode
createSecurityPolicyNoneEndpoint(UA_ServerConfig *conf, UA_Endpoint *endpoint,
                                 const UA_ByteString *cert) {
    UA_EndpointDescription_init(&endpoint->endpointDescription);

    endpoint->securityPolicy = NULL;
    endpoint->endpointDescription.securityMode = UA_MESSAGESECURITYMODE_NONE;
    endpoint->endpointDescription.securityPolicyUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#None");
    endpoint->endpointDescription.transportProfileUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");

    /* enable anonymous and username/password */
    size_t policies = 2;
    endpoint->endpointDescription.userIdentityTokens = (UA_UserTokenPolicy*)
        UA_Array_new(policies, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    if(!endpoint->endpointDescription.userIdentityTokens)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    endpoint->endpointDescription.userIdentityTokensSize = policies;

    endpoint->endpointDescription.userIdentityTokens[0].tokenType =
        UA_USERTOKENTYPE_ANONYMOUS;
    endpoint->endpointDescription.userIdentityTokens[0].policyId =
        UA_STRING_ALLOC(ANONYMOUS_POLICY);

    endpoint->endpointDescription.userIdentityTokens[1].tokenType =
        UA_USERTOKENTYPE_USERNAME;
    endpoint->endpointDescription.userIdentityTokens[1].policyId =
        UA_STRING_ALLOC(USERNAME_POLICY);

    if(cert)
        UA_String_copy(cert, &endpoint->endpointDescription.serverCertificate);

    UA_ApplicationDescription_copy(&conf->applicationDescription,
                                   &endpoint->endpointDescription.server);

    return UA_STATUSCODE_GOOD;
}

UA_ServerConfig *
UA_ServerConfig_new_minimal(UA_UInt16 portNumber,
                            const UA_ByteString *certificate) {
    UA_ServerConfig *conf = (UA_ServerConfig*)UA_malloc(sizeof(UA_ServerConfig));
    if(!conf)
        return NULL;

    /* --> Start setting the default static config <-- */

    memset(conf, 0, sizeof(UA_ServerConfig));
    conf->nThreads = 1;
    conf->logger = UA_Log_Stdout;

    /* Server Description */
    conf->buildInfo = (UA_BuildInfo) {
        UA_STRING_STATIC(PRODUCT_URI),
        UA_STRING_STATIC(MANUFACTURER_NAME),
        UA_STRING_STATIC(PRODUCT_NAME),
        UA_STRING_STATIC(VERSION(
                UA_OPEN62541_VER_MAJOR,
                UA_OPEN62541_VER_MINOR,
                UA_OPEN62541_VER_PATCH,
                UA_OPEN62541_VER_LABEL)),
        UA_STRING_STATIC(__DATE__ " " __TIME__),
        0
    };

    conf->applicationDescription = (UA_ApplicationDescription) {
        UA_STRING_STATIC(APPLICATION_URI),
        UA_STRING_STATIC(PRODUCT_URI), {
            UA_STRING_STATIC("en"),
            UA_STRING_STATIC(APPLICATION_NAME)
        },
        UA_APPLICATIONTYPE_SERVER,
        UA_STRING_STATIC_NULL,
        UA_STRING_STATIC_NULL,
        0, NULL
    };

#ifdef UA_ENABLE_DISCOVERY
    conf->mdnsServerName = (UA_String){0, NULL};
    conf->serverCapabilitiesSize = 0;
    conf->serverCapabilities = NULL;
#endif

    /* Custom DataTypes */
    conf->customDataTypesSize = 0;
    conf->customDataTypes = NULL;

    /* Networking */
    conf->networkLayersSize = 0;
    conf->networkLayers = NULL;

    /* Endpoints */
    conf->endpoints = (UA_Endpoints){0, NULL};

    /* Access Control */
    conf->accessControl = (UA_AccessControl) {
        true, true,
        activateSession_default,
        closeSession_default,
        getUserRightsMask_default,
        getUserAccessLevel_default,
        getUserExecutable_default,
        getUserExecutableOnObject_default,
        allowAddNode_default,
        allowAddReference_default,
        allowDeleteNode_default,
        allowDeleteReference_default };

    /* Limits for SecureChannels */
    conf->maxSecureChannels = 40;
    conf->maxSecurityTokenLifetime = 10 * 60 * 1000; /* 10 minutes */

    /* Limits for Sessions */
    conf->maxSessions = 100;
    conf->maxSessionTimeout = 60.0 * 60.0 * 1000.0; /* 1h */

    /* Limits for Subscriptions */
    conf->publishingIntervalLimits = (UA_DoubleRange){100.0, 3600.0 * 1000.0};
    conf->lifeTimeCountLimits = (UA_UInt32Range){3, 15000};
    conf->keepAliveCountLimits = (UA_UInt32Range){1, 100};
    conf->maxNotificationsPerPublish = 1000;
    conf->maxRetransmissionQueueSize = 0; /* unlimited */

    /* Limits for MonitoredItems */
    conf->samplingIntervalLimits = (UA_DoubleRange){50.0, 24.0 * 3600.0 * 1000.0};
    conf->queueSizeLimits = (UA_UInt32Range){1, 100};

#ifdef UA_ENABLE_DISCOVERY
    conf->discoveryCleanupTimeout = 60 * 60;
#endif

    /* --> Finish setting the default static config <-- */

    /* Add a network layer */
    conf->networkLayers = (UA_ServerNetworkLayer*)
        UA_malloc(sizeof(UA_ServerNetworkLayer));
    if(!conf->networkLayers) {
        UA_free(conf);
        return NULL;
    }
    conf->networkLayers[0] =
        UA_ServerNetworkLayerTCP(UA_ConnectionConfig_default, portNumber);
    conf->networkLayersSize = 1;

    /* Allocate the endpoint */
    conf->endpoints.endpoints = (UA_Endpoint*)UA_malloc(sizeof(UA_Endpoint));
    if(!conf->endpoints.endpoints) {
        conf->networkLayers[0].deleteMembers(&conf->networkLayers[0]);
        UA_free(conf->networkLayers);
        UA_free(conf);
        return NULL;
    }
    conf->endpoints.count = 1;

    /* Populate the endpoint */
    UA_StatusCode retval =
        createSecurityPolicyNoneEndpoint(conf, &conf->endpoints.endpoints[0],
                                         certificate);
    if(retval != UA_STATUSCODE_GOOD) {
        conf->networkLayers[0].deleteMembers(&conf->networkLayers[0]);
        UA_free(conf->networkLayers);
        UA_free(conf->endpoints.endpoints);
        UA_free(conf);
        return NULL;
    }

    return conf;
}

void
UA_ServerConfig_delete(UA_ServerConfig *config) {
    if(!config)
        return;

    UA_BuildInfo_deleteMembers(&config->buildInfo);
    UA_ApplicationDescription_deleteMembers(&config->applicationDescription);

    for(size_t i = 0; i < config->endpoints.count; ++i) {
        UA_EndpointDescription_deleteMembers(&config->endpoints.endpoints[i].endpointDescription);
    }

    for(size_t i = 0; i < config->networkLayersSize; ++i) {
        config->networkLayers[i].deleteMembers(&config->networkLayers[i]);
    }

    UA_free(config->endpoints.endpoints);
    UA_free(config->networkLayers);
    UA_free(config);
}

/***************************/
/* Default Client Settings */
/***************************/

const UA_ClientConfig UA_ClientConfig_default = {
    5000, /* .timeout, 5 seconds */
    10 * 60 * 1000, /* .secureChannelLifeTime, 10 minutes */
    UA_Log_Stdout, /* .logger */
    /* .localConnectionConfig */
    {0, /* .protocolVersion */
        65535, /* .sendBufferSize, 64k per chunk */
        65535, /* .recvBufferSize, 64k per chunk */
        0, /* .maxMessageSize, 0 -> unlimited */
        0}, /* .maxChunkCount, 0 -> unlimited */
    UA_ClientConnectionTCP, /* .connectionFunc */

    0, /* .customDataTypesSize */
    NULL /*.customDataTypes */
};

/****************************************/
/* Default Client Subscription Settings */
/****************************************/

#ifdef UA_ENABLE_SUBSCRIPTIONS

const UA_SubscriptionSettings UA_SubscriptionSettings_default = {
    500.0, /* .requestedPublishingInterval */
    10000, /* .requestedLifetimeCount */
    1, /* .requestedMaxKeepAliveCount */
    10, /* .maxNotificationsPerPublish */
    true, /* .publishingEnabled */
    0 /* .priority */
};

#endif
