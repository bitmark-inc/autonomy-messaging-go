# Autonomy Messaging Go

The messaging protocol for making communications between Autonomy pods.

## Usage

Before using the messaging library, it asumes that a user has already get a new authentication token from the Autonomy API server.

### Setup

First, create a messaging client:
```go
messagingClient := messaging.New(
	&http.Client{Timeout: 10 * time.Second},
	"http://localhost:8080",
	"authentication-token",
	"/path/to/messaging.db",
)
```

And register an account:
```go
messagingClient.RegisterAccount()
```

After that you need to register pre-keys so that other client can start conversations with you:
```go
messagingClient.RegisterKeys()
```


Once everything is done, we can create a websocket connection to send and receive messages:
```go
wsClient := messagingClient.NewWSClient()
```

### Send and Receive

`WhisperMessages` returns a channel of messages.

```go
messages := wsClient.WhisperMessages()
m := <-messages
```

For sending messages to others, we can use `SendWhisperMessages`

```go
wsClient.SendWhisperMessages("<destination DID>", device_id, responseBody)
```
