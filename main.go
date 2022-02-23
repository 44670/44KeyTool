// A SSH agent using usb key

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"go.bug.st/serial"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var optSerialPort = flag.String("port", "", "serial port (e.g. COM3)")
var serialPort serial.Port

func devClearInputBuffer() {
	// Recv data until timeout
	buf := make([]byte, 1024)
	for {
		n, err := serialPort.Read(buf)
		if err != nil {
			log.Fatal("devClearInputBuffer read failed:", err)
		}
		if n == 0 {
			break
		}
	}
}

func devReset() {
	serialPort.Write([]byte("\n"))
	devClearInputBuffer()
}

func devCmdCall(cmd string, timeout int, requestUserConfirm bool) (string, error) {
	arr := strings.Split(cmd, ",")
	log.Println("devCmdCall:", arr[0], "...")
	if requestUserConfirm {
		timeout += 30
		fmt.Println(`=== Waiting for User Confirmation... ===
Please press the "BOOT" button on the device in 30 seconds,
and hold it for one second.
=====================================================`)
	}
	timeout = timeout * (1000 / 200)

	devClearInputBuffer()
	_, err := serialPort.Write([]byte(cmd + "\n"))
	if err != nil {
		log.Fatal("unable to write to serial port:", err)
	}
	timeoutCnt := 0
	dataRead := ""
	ret := ""
	buf := make([]byte, 1024)
	for {
		n, err := serialPort.Read(buf)
		if err != nil {
			log.Fatal("unable to read from serial port:", err)
		}
		if n == 0 {
			timeoutCnt++
			if timeoutCnt > timeout {
				return "", fmt.Errorf("timeout")
			}
			continue
		}
		dataRead += string(buf[:n])
		for {
			idx := strings.Index(dataRead, "\n")
			if idx == -1 {
				break
			}
			line := dataRead[:idx]
			log.Println("dev:", line)
			dataRead = dataRead[idx+1:]
			if len(line) > 0 {
				if line[0] == '+' {
					ret = line
				}
			}
		}
		if ret != "" {
			break
		}
	}
	return ret, nil
}

func devGetPublicKey(usage string) (ssh.PublicKey, error) {
	// Get 32-byte ed25519 public key
	ret, err := devCmdCall("+PUBKEY,ed25519-"+usage, 10, false)
	if err != nil {
		return nil, err
	}
	arr := strings.Split(ret, ",")
	if (arr[0] != "+OK") || (len(arr) != 2) {
		return nil, fmt.Errorf("dev error: %s", ret)
	}
	rawPubKey, err := hex.DecodeString(arr[1])
	if err != nil {
		return nil, err
	}
	// Convert to ssh.PublicKey
	pubKey, err := ssh.NewPublicKey(ed25519.PublicKey(rawPubKey))
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func devSign(usage string, data []byte) (*ssh.Signature, error) {
	ret, err := devCmdCall(fmt.Sprintf("+SIGN,ed25519-%s,%s", usage, hex.EncodeToString(data)), 80, true)
	if err != nil {
		return nil, err
	}
	arr := strings.Split(ret, ",")
	if (arr[0] != "+OK") || (len(arr) != 2) {
		return nil, fmt.Errorf("dev error: %s", ret)
	}
	rawSig, err := hex.DecodeString(arr[1])
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{
		Format: ssh.KeyAlgoED25519,
		Blob:   rawSig,
	}, nil

}

func devFormat(entropy []byte) error {
	if len(entropy) != 32 {
		return fmt.Errorf("entropy must be 32 bytes")
	}
	ret, err := devCmdCall(fmt.Sprintf("+FORMAT,%s", hex.EncodeToString(entropy)), 120, true)
	if err != nil {
		return err
	}
	arr := strings.Split(ret, ",")
	if arr[0] != "+OK" {
		return fmt.Errorf("dev error: %s", ret)
	}
	return nil
}

func devSetupUserSeed(pwdHash []byte) error {
	if len(pwdHash) != 32 {
		return fmt.Errorf("pwdHash must be 32 bytes")
	}
	ret, err := devCmdCall(fmt.Sprintf("+USERSEED,%s", hex.EncodeToString(pwdHash)), 120, true)
	if err != nil {
		return err
	}
	arr := strings.Split(ret, ",")
	if arr[0] != "+OK" {
		return fmt.Errorf("dev error: %s", ret)
	}
	return nil
}

func devWebPwd(domain string) ([]byte, error) {
	usage := "webpwd-" + strings.ReplaceAll(domain, ",", "-")
	if len(usage) > 128 {
		return nil, fmt.Errorf("usage too long")
	}
	ret, err := devCmdCall(fmt.Sprintf("+WEBPWD,%s", usage), 120, true)
	if err != nil {
		return nil, err
	}
	arr := strings.Split(ret, ",")
	if arr[0] != "+OK" {
		return nil, fmt.Errorf("dev error: %s", ret)
	}
	rawPwd, err := hex.DecodeString(arr[1])
	if err != nil {
		return nil, err
	}
	return rawPwd, nil
}

type MyAgent struct {
}

func (a *MyAgent) List() ([]*agent.Key, error) {
	log.Println("List called...")
	pub, err := devGetPublicKey("ssh-0")
	if err != nil {
		log.Println("List error:", err)
		return nil, err
	}
	return []*agent.Key{
		{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: "ssh-0",
		},
	}, nil
}

func (a *MyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	log.Println("Sign called...")
	sig, err := devSign("ssh-0", data)
	if err != nil {
		log.Println("Sign error:", err)
		return nil, err
	}
	return sig, nil
}

func (a *MyAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("not supported")
}

func (a *MyAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("not supported")
}

func (a *MyAgent) RemoveAll() error {
	return fmt.Errorf("not supported")
}

func (a *MyAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("not supported")
}

func (a *MyAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("not supported")
}

func (a *MyAgent) Signers() ([]ssh.Signer, error) {
	return nil, nil
}

var myAgent = &MyAgent{}

func FormatDevice() {
	entropyPool := ""
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("Please enter some random text (>64 chars):")
		// Read a text line from terminal
		scanner.Scan()
		entropyPool += scanner.Text()
		fmt.Println("len(entropyPool): ", len(entropyPool))
		if len(entropyPool) > 64 {
			break
		}
	}
	// SHA256 hash the entropy pool
	h := sha256.New()
	h.Write([]byte(entropyPool))
	entropy := h.Sum(nil)
	fmt.Println("Entropy:", hex.EncodeToString(entropy))
	err := devFormat(entropy)
	if err != nil {
		log.Fatal("Unable to format device:", err)
	}
	fmt.Println("Device formatted successfully!")
}

func AskPasswordAndSetupUserSeed() {
	fmt.Println("The key will be generated with your password and the seed stored on the device.")
	fmt.Println("Please enter your password:")
	// Read a password from terminal
	pwd, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal("unable to read password:", err)
	}
	if len(pwd) < 8 {
		log.Fatal("password must be at least 8 characters long")
	}
	fmt.Println("Please wait...")
	// Agron2 hash the password
	pwdHash := argon2.IDKey(pwd, []byte("44KeyGenerateUserPasswordHash!"), 50, 512*1024, 4, 32)
	err = devSetupUserSeed(pwdHash)
	if err != nil {
		log.Fatal("unable to setup user seed:", err)
	}
	fmt.Println("User seed setup successfully!")
}

func GenWebPwd() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Please enter the domain name (e.g. example.com):")
	scanner.Scan()
	domain := scanner.Text()
	if len(domain) < 3 {
		log.Fatal("domain name must be at least 3 characters long")
	}
	fmt.Println("Index (default 0):")
	scanner.Scan()
	idx := scanner.Text()
	if idx == "" {
		idx = "0"
	}
	rawPwd, err := devWebPwd(fmt.Sprintf("%s-%s", idx, domain))
	if err != nil {
		log.Fatal("unable to generate web password:", err)
	}

	fmt.Printf("%s!%s\n", base64.StdEncoding.EncodeToString(rawPwd[:9]), idx)

}

func main() {
	optWebPwd := flag.Bool("webpwd", false, "generate web password")
	optFormat := flag.Bool("format", false, "Format the device, clear all data and generate a new seed for keys")
	flag.Parse()
	if *optSerialPort == "" {
		fmt.Println("-port is required, available serial ports:")
		// Print available serial ports
		l, _ := serial.GetPortsList()
		for _, v := range l {
			fmt.Println(v)
		}
		return
	}
	// Open serial port
	var err error
	serialPort, err = serial.Open(*optSerialPort, &serial.Mode{
		BaudRate: 115200,
		DataBits: 8,
		StopBits: serial.OneStopBit,
		Parity:   serial.NoParity,
	})
	if err != nil {
		log.Fatal("unable to open serial port:", err)
	}
	// Clear RTS and DTR
	serialPort.SetDTR(false)
	serialPort.SetRTS(false)
	serialPort.SetReadTimeout(time.Millisecond * 200)
	devReset()
	if *optFormat {
		FormatDevice()
		return
	}
	pubKey, err := devGetPublicKey("ssh-0")
	if err != nil {
		if strings.Contains(err.Error(), "user seed not set") {
			AskPasswordAndSetupUserSeed()
			pubKey, err = devGetPublicKey("ssh-0")
			if err != nil {
				log.Fatal("unable to get public key:", err)
			}
		} else {
			log.Fatal("unable to get public key:", err)
		}
	}
	if *optWebPwd {
		GenWebPwd()
		return
	}
	// Print public key in authorized_keys format
	fmt.Println("\n=== Public key in ssh format, add following line to ~/.ssh/authorized_keys on your remote servers ===")
	fmt.Println(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))), " my-44key")
	fmt.Println("=== End of public key ===\n")
	RunSSHServer()
}
