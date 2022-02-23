//go:build windows
// +build windows

package main

import (
	"log"

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

func RunSSHServer() {
	// Start a ssh agent on windows named pipe
	err := ServeSSHAgentOnPipe(`\\.\pipe\openssh-ssh-agent`)
	if err != nil {
		log.Fatal("ListenPipe failed:", err)
	}
}
