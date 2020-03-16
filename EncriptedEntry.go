package main

// EncriptedEntry represents a WinSCP server entry.
type EncriptedEntry struct {
	username          string // Server entry username
	host              string // Server entry hostname
	encryptedPassword string // Server entry encryped password

	encryptedPasswordBytes []byte // Encrypted password byte array
}

// GetCryptedPasswordLength obtains crypted password length from crypted password byte array.
func (e *EncriptedEntry) GetCryptedPasswordLength(flag byte) byte {
	var cryptedPasswordlength byte = 0
	if flag == PasswordFlag {
		_ = e.DecryptNextCharacter()                     // Ignore two characters of the encryptedPasswordBytes.
		cryptedPasswordlength = e.DecryptNextCharacter() // DecryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
	} else {
		cryptedPasswordlength = flag
	}
	toBeDeleted := e.DecryptNextCharacter() // DecryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
	e.encryptedPasswordBytes = e.encryptedPasswordBytes[toBeDeleted*2:]
	return cryptedPasswordlength
}

// GetPassword obtains clear password from crypted password byte array
func (e *EncriptedEntry) GetPassword(cryptedPasswordlength byte) string {
	var decryptedPassword string
	for i := byte(0); i < cryptedPasswordlength; i++ {
		character := e.DecryptNextCharacter()  // DecryptNextCharacter alters the encryptedPasswordBytes variable to remove already parsed characters.
		decryptedPassword += string(character) // Add decrypted character to the result variable.
	}
	return decryptedPassword
}

// DecryptNextCharacter decrypts next character from byte array.
// Alters the byte array to remove already parsed bytes.
func (e *EncriptedEntry) DecryptNextCharacter() byte {
	if len(e.encryptedPasswordBytes) <= 0 {
		// In case encryptedPasswordBytes param was empty,
		// stop the flow here returning '0'.
		return 0
	}

	a := e.encryptedPasswordBytes[0]                        // Obtain first character to parse.
	b := e.encryptedPasswordBytes[1]                        // Obtain second character to parse.
	e.encryptedPasswordBytes = e.encryptedPasswordBytes[2:] // Remove already parsed characters.
	return DecryptCharacter(a, b)
}
