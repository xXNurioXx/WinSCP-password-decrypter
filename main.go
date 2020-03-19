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
		PrintHelp()
		return
	}

	if args[0] == "ini" {
		// In case 'ini' argument was provided,
		// start the decryption of ini file.
		var iniPath string
		if len(args) == 2 {
			iniPath = args[1]
		} else {
			iniPath = GetDefaultWinSCPIniFilePath()
		}
		DecryptIni(iniPath)
		return
	}

	// In case any argument matches a different operation,
	// perform the default decryption operation.
	fmt.Println(Decrypt(args[0], args[1], args[2]))
}

// PrintHelp prints a help message with instructions about the application usage.
func PrintHelp() {
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
	fmt.Printf("  Default value <filepath>: %s\n", GetDefaultWinSCPIniFilePath())
	return
}

// GetDefaultWinSCPIniFilePath obtains default WinSCP configuration file.
func GetDefaultWinSCPIniFilePath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir + "\\AppData\\Roaming\\winSCP.ini"
}

// DecryptIni decrypts all entries from a WinSCP's ini file.
func DecryptIni(filepath string) {
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
			fmt.Printf("  Password: %s\n", Decrypt(c.Key("HostName").Value(), c.Key("UserName").Value(), c.Key("Password").Value()))
			fmt.Println("========================")
		}
	}

}

// Decrypt decripts a specific server password.
func Decrypt(host, username, password string) string {
	// Build 'encryptedPasswordBytes' variable.
	encryptedPasswordBytes := GetCryptedPasswordBytes(password)

	// Extract 'flag' and 'cryptedPasswordlength' variables
	flag, encryptedPasswordBytes := DecryptNextCharacter(encryptedPasswordBytes) // decryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
	cryptedPasswordlength, encryptedPasswordBytes := GetCryptedPasswordLength(flag, encryptedPasswordBytes)

	// Build 'clearpass' variable
	clearpass := GetPassword(cryptedPasswordlength, encryptedPasswordBytes)

	// Apply correction to the 'clearpass' variable.
	if flag == PasswordFlag {
		// The clearpass will contians the username, host and password.
		// Substring username and host from the result password.
		key := username + host
		clearpass = clearpass[len(key):]
	}
	return clearpass
}

// GetCryptedPasswordBytes obtains the crypted password byte array.
func GetCryptedPasswordBytes(password string) []byte {
	encryptedPasswordBytes := []byte{}
	for i := 0; i < len(password); i++ {
		val, _ := strconv.ParseInt(string(password[i]), 16, 8)
		encryptedPasswordBytes = append(encryptedPasswordBytes, byte(val))
	}
	return encryptedPasswordBytes
}

// GetCryptedPasswordLength obtains crypted password length from crypted password byte array.
func GetCryptedPasswordLength(flag byte, encryptedPasswordBytes []byte) (byte, []byte) {
	var cryptedPasswordlength byte = 0
	if flag == PasswordFlag {
		_, encryptedPasswordBytes = DecryptNextCharacter(encryptedPasswordBytes)                     // Ignore two characters of the encryptedPasswordBytes.
		cryptedPasswordlength, encryptedPasswordBytes = DecryptNextCharacter(encryptedPasswordBytes) // decryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
	} else {
		cryptedPasswordlength = flag
	}
	toBeDeleted, encryptedPasswordBytes := DecryptNextCharacter(encryptedPasswordBytes) // decryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
	encryptedPasswordBytes = encryptedPasswordBytes[toBeDeleted*2:]
	return cryptedPasswordlength, encryptedPasswordBytes
}

// GetPassword obtains clear password from crypted password byte array
func GetPassword(cryptedPasswordlength byte, encryptedPasswordBytes []byte) string {
	var i, character byte
	var decryptedPassword string

	for i = 0; i < cryptedPasswordlength; i++ {
		character, encryptedPasswordBytes = DecryptNextCharacter(encryptedPasswordBytes) // decryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
		decryptedPassword += string(character)                                           // Add decrypted character to the result variable.
	}
	return decryptedPassword
}

// DecryptNextCharacter decrypts next character from byte array.
// Alters the byte array to remove already parsed bytes.
func DecryptNextCharacter(encryptedPasswordBytes []byte) (byte, []byte) {
	if len(encryptedPasswordBytes) <= 0 {
		// In case encryptedPasswordBytes param was empty,
		// stop the flow here returning '0'.
		return 0, encryptedPasswordBytes
	}

	a := encryptedPasswordBytes[0]                      // Obtain first character to parse.
	b := encryptedPasswordBytes[1]                      // Obtain second character to parse.
	encryptedPasswordBytes = encryptedPasswordBytes[2:] // Remove already parsed characters.
	return DecryptCharacter(a, b), encryptedPasswordBytes
}

// DecryptCharacter decrypts character from two bytes.
func DecryptCharacter(a, b byte) byte {
	return ^(((a << 4) + b) ^ PasswordMagic) & PasswordFlag
}
