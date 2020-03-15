package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"
)

// WinSCP password encryption/decryption salts.
const (
	PasswordMagic = 0xA3
	PasswordFlag  = 0xFF
)

func main() {
	args := os.Args[1:]
	if len(args) != 3 && len(args) != 2 {
		// In case provided arguments doesn't match the
		// application usage, print application usage message.
		printHelp()
		return
	}

	if args[0] == "ini" {
		// In case 'ini' argument was provided,
		// start the decryption of ini file.
		var iniPath string
		if len(args) == 2 {
			iniPath = args[1]
		} else {
			iniPath = defaultWinSCPIniFilePath()
		}
		decryptIni(iniPath)
		return
	}

	// In case any argument matches a different operation,
	// perform the default decryption operation.
	fmt.Println(decrypt(args[0], args[1], args[2]))
}

func printHelp() {
	fmt.Println("WinSCP stored password finder")

	// WinSCP's password manual decryption mode.
	fmt.Println("Registry:")
	fmt.Println("  Open regedit and navigate to [HKEY_CURRENT_USER\\Software\\Martin Prikryl\\WinSCP 2\\Sessions] to get the hostname, username and encrypted password")
	if runtime.GOOS == "windows" {
		fmt.Println("  Usage winscppasswd.exe <host> <username> <encrypted_password>")
	} else {
		fmt.Println("  Usage ./winscppasswd <host> <username> <encrypted_password>")
	}

	// WinSCP's ini file mode.
	fmt.Println("\n\nWinSCP.ini:")
	if runtime.GOOS == "windows" {
		fmt.Println("  Usage winscppasswd.exe ini [<filepath>]")
	} else {
		fmt.Println("  Usage ./winscppasswd ini [<filepath>]")
	}
	fmt.Printf("  Default value <filepath>: %s\n", defaultWinSCPIniFilePath())
	return
}

func defaultWinSCPIniFilePath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir + "\\AppData\\Roaming\\winSCP.ini"
}

func decryptIni(filepath string) {
	cfg, err := ini.InsensitiveLoad(filepath)
	if err != nil {
		panic(err)
	}

	// Print every entry of the configuration that has password field.
	for _, c := range cfg.Sections() {
		if c.HasKey("Password") {
			name, _ := url.PathUnescape(strings.TrimPrefix(c.Name(), "sessions\\"))
			fmt.Printf("%s\n", name)
			fmt.Printf("  Hostname: %s\n", c.Key("HostName").Value())
			fmt.Printf("  Username: %s\n", c.Key("UserName").Value())
			fmt.Printf("  Password: %s\n", decrypt(c.Key("HostName").Value(), c.Key("UserName").Value(), c.Key("Password").Value()))
			fmt.Println("========================")
		}
	}

}

func decrypt(host, username, password string) string {
	// Build 'passbytes' variable
	passbytes := []byte{}
	for i := 0; i < len(password); i++ {
		val, _ := strconv.ParseInt(string(password[i]), 16, 8)
		passbytes = append(passbytes, byte(val))
	}

	// Build 'flag' variable
	var flag byte
	flag, passbytes = decryptNextCharacter(passbytes) // decryptNextCharacter alters the passbytes variable to remove already parsed characters.

	// Build 'length' variable
	var cryptedPasswordlength byte = 0
	if flag == PasswordFlag {
		_, passbytes = decryptNextCharacter(passbytes)                     // Ignore two characters of the passbytes.
		cryptedPasswordlength, passbytes = decryptNextCharacter(passbytes) // decryptNextCharacter alters the passbytes variable to remove already parsed characters.
	} else {
		cryptedPasswordlength = flag
	}
	toBeDeleted, passbytes := decryptNextCharacter(passbytes) // decryptNextCharacter alters the passbytes variable to remove already parsed characters.
	passbytes = passbytes[toBeDeleted*2:]

	// Build 'clearpass' variable
	clearpass := ""
	var (
		i   byte
		val byte
	)
	for i = 0; i < cryptedPasswordlength; i++ {
		val, passbytes = decryptNextCharacter(passbytes) // decryptNextCharacter alters the passbytes variable to remove already parsed characters.
		clearpass += string(val)                         // Add decrypted character to the result variable.
	}

	// Apply correction to the 'clearpass' variable.
	if flag == PasswordFlag {
		// The clearpass will contians the username, host and password.
		// Substring username and host from the result password.
		key := username + host
		clearpass = clearpass[len(key):]
	}
	return clearpass
}

func decryptNextCharacter(passbytes []byte) (byte, []byte) {
	if len(passbytes) <= 0 {
		// In case passbytes param was empty,
		// stop the flow here returning '0'.
		return 0, passbytes
	}

	a := passbytes[0]         // Obtain first character to parse.
	b := passbytes[1]         // Obtain second character to parse.
	passbytes = passbytes[2:] // Remove already parsed characters.
	return ^(((a << 4) + b) ^ PasswordMagic) & PasswordFlag, passbytes
}
