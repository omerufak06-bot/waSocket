# waSocket
[![Go Reference](https://pkg.go.dev/badge/github.com/idlethorn/waSocket.svg)](https://pkg.go.dev/github.com/idlethorn/waSocket)

waSocket is a Go library for the WhatsApp web multidevice API.
This is a fork that use a workaround for slow groupm essage, and some unmerged PR
## Discussion
<!-- Matrix room: [#waSocket:maunium.net](https://matrix.to/#/#waSocket:maunium.net) -->
Whatsapp Group: https://chat.whatsapp.com/BDI3NMjO7vW7RlOqgdxtmw

For questions about the WhatsApp protocol (like how to send a specific type of
message), you can also use the [WhatsApp protocol Q&A] section on GitHub
discussions.

<!-- [WhatsApp protocol Q&A]: https://github.com/tulir/waSocket/discussions/categories/whatsapp-protocol-q-a -->

## Usage
The [godoc](https://pkg.go.dev/github.com/idlethorn/waSocket) includes docs for all methods and event types.
There's also a [simple example](https://pkg.go.dev/github.com/idlethorn/waSocket#example-package) at the top.

## Features
Most core features are already present:

* Sending messages to private chats and groups (both text and media)
* Receiving all messages
* Managing groups and receiving group change events
* Joining via invite messages, using and creating invite links
* Sending and receiving typing notifications
* Sending and receiving delivery and read receipts
* Reading and writing app state (contact list, chat pin/mute status, etc)
* Sending and handling retry receipts if message decryption fails
* Sending status messages (experimental, may not work for large contact lists)

Things that are not yet implemented:

* Sending broadcast list messages (this is not supported on WhatsApp web either)
* Calls
