# Authentication through GRPC

## Overview

The GRPC connector allows username/password based authentication.

The connector executes a grpc request on a configurable service. For implementation reasons a protobuf file (defining the reuquest and response messages) and its generated go code are part of the package. Of cource this proto file can also be directly imported into the service implementing the authentication and refresh methods.


## Configuration

The following describes the config file that can be used by the GRPC connector to authenticate a user.

```yaml
connectors:
- type: grpc
  # Required field for connector id.
  id: grpc
  # Required field for connector name.
  name: GRPC
  config:
    # Host and port of the GRPC service in the form "host:port".
    host: grpc.example.com:443

    # Following field is required if the GRPC service is not using TLS.
    #
    # insecureNoSSL: true

    # The path to the public key of your (grpc) servers certificate.
    cert: /path/to/public.crt

    # The grpc service and method name where the auth request is sent to.
	  authMethodName: /proto.ServiceName/MethodName

    # The grpc service and method name where the refresh request is sent to.
	  refreshMethodName: /proto.ServiceName/MethodName
```
A minimal working configuration might look like:

```yaml
connectors:
- type: grpc
  id: grpc
  name: IdentityService
  config:
    host: identity-service:80
    insecureNoSSL: true
    authMethodName: /proto.IdentityService/CheckIdentity
    refreshMethodName: /proto.IdentityService/RefreshIdentity
```

or more securely:

```yaml
connectors:
- type: grpc
  id: grpc
  name: IdentityService
  config:
    host: identity-service:443
    cert: /identity.crt
    authMethodName: /proto.IdentityService/CheckIdentity
    refreshMethodName: /proto.IdentityService/RefreshIdentity
```