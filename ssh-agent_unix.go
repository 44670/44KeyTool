//go:build !windows
// +build !windows

package main

import (
	"log"
	"net"

	"golang.org/x/crypto/ssh/agent"
)

func ServeSSHAgentOnUnixDomainSocket(path string) error {
	// Start a ssh agent on unix domain socket
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Println("SSH agent started at ", path)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			// Handle the connection
			err := agent.ServeAgent(myAgent, conn)
			log.Println("Agent conn closed:", err)
		}()
	}
}

func RunSSHServer() {

	log.Println(`=== Set the following environment variable before using ssh ===
	export SSH_AUTH_SOCK=/tmp/44ssh
============================================================`)
	// Start a ssh agent on unix domain socket
	err := ServeSSHAgentOnUnixDomainSocket(`/tmp/44ssh`)
	if err != nil {
		log.Fatal("ListenUnix failed:", err)
	}

}
