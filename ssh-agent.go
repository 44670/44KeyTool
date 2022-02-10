package main

import (
	"log"
	"net"
	"runtime"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

func ServeSSHAgentOnPipe(path string) error {
	// Start a ssh agent on windows named pipe
	var pipeCfg = &winio.PipeConfig{}
	pipe, err := winio.ListenPipe(`\\.\pipe\openssh-ssh-agent`, pipeCfg)
	if err != nil {
		return err
	}
	defer pipe.Close()
	log.Println("SSH agent started at ", path)
	for {
		conn, err := pipe.Accept()
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

func ServerSSHAgentOnUnixDomainSocket(path string) error {
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
	if runtime.GOOS == "windows" {
		// Start a ssh agent on windows named pipe
		err := ServeSSHAgentOnPipe(`\\.\pipe\openssh-ssh-agent`)
		if err != nil {
			log.Fatal("ListenPipe failed:", err)
		}
	} else {
		log.Println(`=== Set the following environment variable before using ssh ===
	export SSH_AUTH_SOCK=/tmp/44ssh
============================================================`)
		// Start a ssh agent on unix domain socket
		err := ServerSSHAgentOnUnixDomainSocket(`/tmp/44ssh`)
		if err != nil {
			log.Fatal("ListenUnix failed:", err)
		}
	}
}
