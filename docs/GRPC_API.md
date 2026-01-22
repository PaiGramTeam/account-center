# Paigram gRPC API Documentation

## Overview

Paigram provides a high-performance gRPC API for bot clients to access user data and authentication services. The API uses Protocol Buffers (protobuf) for efficient serialization and supports multiple programming languages.

## Getting Started

### Server Configuration

Add the following to your `config.yaml` to enable gRPC:

```yaml
grpc:
  enabled: true
  port: 50051
```

### Authentication

All API calls (except bot registration and login) require authentication using a Bearer token in the metadata:

```
authorization: Bearer <access_token>
```

## Services

### 1. BotAuthService

Handles bot registration, authentication, and token management.

#### RegisterBot
Register a new bot client.

**Request:**
```protobuf
message RegisterBotRequest {
  string name = 1;           // Bot display name
  string description = 2;    // Bot description
  BotType type = 3;         // Bot type (TELEGRAM, DISCORD, etc.)
  repeated string scopes = 4; // Required permissions
  string owner_email = 5;    // Owner's email address
}
```

**Response:**
```protobuf
message RegisterBotResponse {
  Bot bot = 1;         // Bot information
  string api_key = 2;  // API key (public)
  string api_secret = 3; // API secret (keep secure!)
}
```

**Example:**
```go
resp, err := client.RegisterBot(ctx, &pb.RegisterBotRequest{
    Name:        "My Bot",
    Description: "A helpful bot",
    Type:        pb.BotType_BOT_TYPE_TELEGRAM,
    Scopes:      []string{"user.read", "user.list"},
    OwnerEmail:  "owner@example.com",
})
```

#### BotLogin
Authenticate bot and receive access tokens.

**Request:**
```protobuf
message BotLoginRequest {
  string api_key = 1;    // Bot's API key
  string api_secret = 2; // Bot's API secret
}
```

**Response:**
```protobuf
message BotLoginResponse {
  string access_token = 1;  // JWT access token
  string refresh_token = 2; // Refresh token
  int64 expires_in = 3;    // Token lifetime in seconds
  string token_type = 4;   // Token type (Bearer)
  Bot bot = 5;            // Bot information
}
```

#### RefreshBotToken
Refresh an expired access token.

**Request:**
```protobuf
message RefreshBotTokenRequest {
  string refresh_token = 1; // Current refresh token
}
```

**Response:**
```protobuf
message RefreshBotTokenResponse {
  string access_token = 1;  // New access token
  string refresh_token = 2; // New refresh token
  int64 expires_in = 3;    // Token lifetime
  string token_type = 4;   // Token type
}
```

### 2. UserService

Provides user data access and management.

#### GetUser
Retrieve a single user by ID or email.

**Request:**
```protobuf
message GetUserRequest {
  oneof identifier {
    uint64 id = 1;      // User ID
    string email = 2;   // User email
  }
}
```

**Response:**
```protobuf
message GetUserResponse {
  User user = 1; // User information with profile and emails
}
```

**Example:**
```go
// Get by ID
resp, err := client.GetUser(ctx, &pb.GetUserRequest{
    Identifier: &pb.GetUserRequest_Id{Id: 123},
})

// Get by email
resp, err := client.GetUser(ctx, &pb.GetUserRequest{
    Identifier: &pb.GetUserRequest_Email{Email: "user@example.com"},
})
```

#### GetUsersByIds
Retrieve multiple users by their IDs.

**Request:**
```protobuf
message GetUsersByIdsRequest {
  repeated uint64 ids = 1; // List of user IDs
}
```

**Response:**
```protobuf
message GetUsersByIdsResponse {
  repeated User users = 1; // List of users
}
```

#### VerifyUser
Verify user credentials (email/password).

**Request:**
```protobuf
message VerifyUserRequest {
  string email = 1;    // User email
  string password = 2; // User password
}
```

**Response:**
```protobuf
message VerifyUserResponse {
  bool valid = 1;     // Validation result
  User user = 2;      // User data (if valid)
  string message = 3; // Response message
}
```

#### GetUserPermissions
Get user's permissions and roles.

**Request:**
```protobuf
message GetUserPermissionsRequest {
  uint64 user_id = 1; // User ID
}
```

**Response:**
```protobuf
message GetUserPermissionsResponse {
  repeated string permissions = 1; // List of permissions
  repeated string roles = 2;      // List of roles
}
```

#### UpdateUserData
Update user profile information.

**Request:**
```protobuf
message UpdateUserDataRequest {
  uint64 user_id = 1;
  optional string display_name = 10;
  optional string avatar_url = 11;
  optional string bio = 12;
  optional string locale = 13;
}
```

**Response:**
```protobuf
message UpdateUserDataResponse {
  User user = 1; // Updated user data
}
```

## Data Types

### User
```protobuf
message User {
  uint64 id = 1;
  string primary_login_type = 2;
  UserStatus status = 3;
  google.protobuf.Timestamp last_login_at = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp updated_at = 6;
  UserProfile profile = 10;
  repeated UserEmail emails = 11;
}
```

### Bot
```protobuf
message Bot {
  string id = 1;
  string name = 2;
  string description = 3;
  BotType type = 4;
  BotStatus status = 5;
  repeated string scopes = 6;
  google.protobuf.Timestamp created_at = 7;
  google.protobuf.Timestamp updated_at = 8;
  google.protobuf.Timestamp last_active_at = 9;
}
```

## Scopes

Available permission scopes for bots:

- `user.read` - Read user information
- `user.list` - List multiple users
- `user.update` - Update user data
- `user.verify` - Verify user credentials
- `admin.all` - Full administrative access

## Error Handling

gRPC uses standard status codes. Common errors:

- `UNAUTHENTICATED` - Missing or invalid authentication
- `PERMISSION_DENIED` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `INVALID_ARGUMENT` - Invalid request parameters
- `INTERNAL` - Server error

## Client Examples

### Go Client

```go
package main

import (
    "context"
    "log"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
    pb "paigram/proto/paigram/v1"
)

func main() {
    // Connect to server
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    // Create clients
    authClient := pb.NewBotAuthServiceClient(conn)
    userClient := pb.NewUserServiceClient(conn)
    
    // Login
    loginResp, err := authClient.BotLogin(context.Background(), &pb.BotLoginRequest{
        ApiKey:    "your_api_key",
        ApiSecret: "your_api_secret",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Create authenticated context
    md := metadata.Pairs("authorization", "Bearer " + loginResp.AccessToken)
    ctx := metadata.NewOutgoingContext(context.Background(), md)
    
    // Get user
    userResp, err := userClient.GetUser(ctx, &pb.GetUserRequest{
        Identifier: &pb.GetUserRequest_Id{Id: 1},
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("User: %+v", userResp.User)
}
```

### Python Client

```python
import grpc
from paigram.proto import user_pb2, user_pb2_grpc

# Connect to server
channel = grpc.insecure_channel('localhost:50051')
stub = user_pb2_grpc.UserServiceStub(channel)

# Create metadata with auth token
metadata = [('authorization', 'Bearer ' + access_token)]

# Make request
request = user_pb2.GetUserRequest(id=1)
response = stub.GetUser(request, metadata=metadata)

print(f"User: {response.user}")
```

### Node.js Client

```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

// Load proto
const packageDefinition = protoLoader.loadSync('proto/paigram/v1/user.proto');
const proto = grpc.loadPackageDefinition(packageDefinition).paigram.v1;

// Create client
const client = new proto.UserService(
    'localhost:50051',
    grpc.credentials.createInsecure()
);

// Create metadata
const metadata = new grpc.Metadata();
metadata.add('authorization', 'Bearer ' + accessToken);

// Make request
client.getUser({id: 1}, metadata, (err, response) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log('User:', response.user);
});
```

## Rate Limiting

API calls are rate-limited per bot:
- 1000 requests per minute for read operations
- 100 requests per minute for write operations

## Best Practices

1. **Token Management**: Store refresh tokens securely and refresh access tokens before expiry
2. **Error Handling**: Implement retry logic with exponential backoff
3. **Connection Pooling**: Reuse gRPC connections for multiple requests
4. **Scope Minimization**: Request only the scopes your bot actually needs
5. **Monitoring**: Track API usage and errors for debugging

## Migration from REST API

If migrating from the REST API:

1. gRPC is typically 2-5x faster for most operations
2. Binary protocol reduces bandwidth usage
3. Strongly typed interfaces prevent errors
4. Bidirectional streaming enables real-time features

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/paigram/issues
- Documentation: https://paigram.docs.example.com
- Email: support@paigram.example.com