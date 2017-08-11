package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"

	"github.com/coreos/dex/connector"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config holds the configuration parameter for the grpc client.
//
// An example config:
//   type: grpc
//   config:
//     host: identity-service:443
//     cert: /identity.crt
//     authMethodName: /proto.IdentityService/CheckIdentity
//
type Config struct {
	// Host and port of the GRPC service in the form "host:port".
	Host string `json:"host"`

	// Required if the GRPC service is not using TLS.
	InsecureNoSSL bool `json:"insecureNoSSL"`

	// The path to the public key of your (grpc) servers certificate.
	Cert string `json:"cert"`

	// The grpc service and method name where the auth request is sent to.
	AuthMethodName string `json:"authMethodName"`

	// The grpc service and method name where the refresh request is sent to.
	RefreshMethodName string `json:"refreshMethodName"`
}

// Open returns an authentication strategy using a grgc interface.
func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	if c.Host == "" {
		return nil, fmt.Errorf("grpc: missing required field host")
	}
	if !c.InsecureNoSSL && c.Cert == "" {
		return nil, fmt.Errorf("grpc: missing required field cert. Please provide a path to the servers public key (or set insecureNoSSL: true)")
	}
	if c.AuthMethodName == "" {
		return nil, fmt.Errorf("grpc: missing required field authMethodName")
	}
	return &grpcConnector{
		Host:              c.Host,
		InsecureNoSSL:     c.InsecureNoSSL,
		Cert:              c.Cert,
		AuthMethodName:    c.AuthMethodName,
		RefreshMethodName: c.RefreshMethodName,
		logger:            logger,
	}, nil
}

type grpcConnector struct {
	Host              string
	InsecureNoSSL     bool
	Cert              string
	AuthMethodName    string
	RefreshMethodName string

	cc *grpc.ClientConn

	logger logrus.FieldLogger
}

// Login implements the connectors Login method providing a mechanism for checking username and password
func (c *grpcConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	var identityMessage *IdentityMessage
	err = c.connect(ctx, func(conn *grpc.ClientConn) error {
		c.cc = conn
		identityMessage, validPass, err = c.checkUserPassword(ctx, &UserPassword{Username: username, Password: password})
		return err

	})
	if err != nil || identityMessage == nil {
		return connector.Identity{}, false, err
	}
	ident, err = c.identityFromMessage(identityMessage)
	if err != nil {
		return connector.Identity{}, validPass, err
	}
	return ident, validPass, err
}

// Refresh implements the connectors Refresh method
func (c *grpcConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var identityMessage *IdentityMessage
	err := c.connect(ctx, func(conn *grpc.ClientConn) error {
		c.cc = conn
		var err error
		identityMessage, err = c.checkUserID(ctx, &UserID{Userid: ident.UserID})
		return err

	})
	if err != nil || identityMessage == nil {
		return ident, fmt.Errorf("grpc: failed to refresh identity: %v", err)
	}
	newIdent, err := c.identityFromMessage(identityMessage)
	if err != nil {
		return ident, err
	}
	return newIdent, err
}

func (c *grpcConnector) connect(ctx context.Context, f func(c *grpc.ClientConn) error) (err error) {
	var conn *grpc.ClientConn
	if c.InsecureNoSSL {
		conn, err = grpc.Dial(c.Host, grpc.WithInsecure())
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %v", c.Host, err)
		}
	} else {
		creds, err := credentials.NewClientTLSFromFile(c.Cert, "")
		if err != nil {
			return fmt.Errorf("could not load tls cert: %s", err)
		}
		conn, err = grpc.Dial(c.Host, grpc.WithTransportCredentials(creds))
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %v", c.Host, err)
		}
	}
	defer conn.Close()

	return f(conn)
}

func (c *grpcConnector) checkUserPassword(ctx context.Context, in *UserPassword, opts ...grpc.CallOption) (*IdentityMessage, bool, error) {
	out := new(IdentityMessage)
	err := grpc.Invoke(ctx, c.AuthMethodName, in, out, c.cc, opts...)
	if err != nil {
		// check if the error is a grpc error representing the unseccessful login
		if grpc.Code(err) == codes.Unauthenticated {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out, true, nil
}

func (c *grpcConnector) checkUserID(ctx context.Context, in *UserID, opts ...grpc.CallOption) (*IdentityMessage, error) {
	out := new(IdentityMessage)
	err := grpc.Invoke(ctx, c.RefreshMethodName, in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *grpcConnector) identityFromMessage(identityMessage *IdentityMessage) (connector.Identity, error) {
	return connector.Identity{
		UserID:   identityMessage.Userid,
		Username: identityMessage.Username,
		Email:    identityMessage.Email}, nil
}
