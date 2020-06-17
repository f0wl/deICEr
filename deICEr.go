package main

import (
	"crypto/rc4"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

func jankyPrettyPrint(unfMessage string) {
	// replace all occurrences of .xyz with ".xyz " :D
	xyzrepd := strings.Replace(unfMessage, ".xyz", ".xyz\n   ", -1)
	// and let's do the same thing for .best
	bestrepd := strings.Replace(xyzrepd, ".best", ".best\n   ", -1)
	// and php...
	phprepd := strings.Replace(bestrepd, ".php", ".php\n   ", -1)

	fmt.Println("\n   Extracted Config:\n\n   ", phprepd)
}

func rc4decrypt(extkey []byte, data []byte) {
	// create a new RC4 Enc/Dec Routine and pass the key
	cipher, ciphErr := rc4.NewCipher(extkey)
	check(ciphErr)
	// decrypt the config
	cipher.XORKeyStream(data, data)
	jankyPrettyPrint(string(data))
}

func main() {
	fmt.Println("\n\n              ▓█████▄ ▓█████  ██▓ ▄████▄  ▓█████  ██▀███")
	fmt.Println("               ▒██▀ ██▌▓█   ▀ ▓██▒▒██▀ ▀█  ▓█   ▀ ▓██ ▒ ██▒")
	fmt.Println("               ░██   █▌▒███   ▒██▒▒▓█    ▄ ▒███   ▓██ ░▄█ ▒")
	fmt.Println("               ░▓█▄   ▌▒▓█  ▄ ░██░▒▓▓▄ ▄██▒▒▓█  ▄ ▒██▀▀█▄  ")
	fmt.Println("               ░▒████▓ ░▒████▒░██░▒ ▓███▀ ░░▒████▒░██▓ ▒██▒")
	fmt.Println("                ▒▒▓  ▒ ░░ ▒░ ░░▓  ░ ░▒ ▒  ░░░ ▒░ ░░ ▒▓ ░▒▓░")
	fmt.Println("                ░ ▒  ▒  ░ ░  ░ ▒ ░  ░  ▒    ░ ░  ░  ░▒ ░ ▒░")
	fmt.Println("                ░ ░  ░    ░    ▒ ░░           ░     ░░   ░ ")
	fmt.Println("                  ░       ░  ░ ░  ░ ░         ░  ░   ░     ")
	fmt.Println("                ░                 ░                        ")
	fmt.Println("\n   ICEDID Config Extractor - Week 0x02 of Zero2Auto (courses.zero2auto.com)")
	fmt.Println("            Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	if len(os.Args) < 2 {
		fmt.Println("   Usage: ./deICEr.go unpacked_ICEDID_Loader.exe")
		os.Exit(1)
	}

	// read the PE
	file := ioReader(os.Args[1])
	f, err := pe.NewFile(file)
	check(err)

	// dump out the contents of the .data section
	rawData, dumpErr := f.Section(".data").Data()

	if dumpErr == nil {
		// slicing out the key
		rc4_key := rawData[:8]
		fmt.Println("   Extracted RC4 Key (UTF-8): ", rc4_key)
		// ...and the ciphertext with the proper offset
		ciphertext := rawData[8:592]
		rc4decrypt(rc4_key, ciphertext)
	}

}
