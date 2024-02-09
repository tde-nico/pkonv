package main

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

var (
	zip  bool
	dec  bool
	ng   bool
	newg bool
	ekey []byte
	dkey []byte
)

func encryptWriter(writer io.Writer) (io.Writer, error) {
	block, err := aes.NewCipher(ekey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if _, err := writer.Write(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	return &cipher.StreamWriter{S: stream, W: writer}, nil
}

func decryptReader(reader io.Reader) (io.Reader, error) {
	block, err := aes.NewCipher(dkey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	return &cipher.StreamReader{S: stream, R: reader}, nil
}

func convert(f *os.File, out *os.File) error {
	var err error

	var dReader io.Reader
	if len(dkey) != 0 {
		dReader, err = decryptReader(f)
		if err != nil {
			log.Fatalf("Error reading %v 'in' file: %v\n", f.Name(), err)
		}
	}

	var gzReader *gzip.Reader
	if dec {
		if len(dkey) != 0 {
			gzReader, err = gzip.NewReader(dReader)
		} else {
			gzReader, err = gzip.NewReader(f)
		}
		if err != nil {
			log.Fatalf("Error reading %v 'in' file: %v\n", f.Name(), err)
		}
		defer gzReader.Close()
	}

	var ngIn *pcapgo.NgReader
	var in *pcapgo.Reader
	if dec {
		if newg {
			ngIn, err = pcapgo.NewNgReader(gzReader, pcapgo.NgReaderOptions{})
		} else {
			in, err = pcapgo.NewReader(gzReader)
		}
	} else {
		if newg {
			if len(dkey) != 0 {
				ngIn, err = pcapgo.NewNgReader(dReader, pcapgo.NgReaderOptions{})
			} else {
				ngIn, err = pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
			}
		} else {
			if len(dkey) != 0 {
				in, err = pcapgo.NewReader(dReader)
			} else {
				in, err = pcapgo.NewReader(f)
			}
		}
	}
	if err != nil {
		log.Fatalf("Error reading %v 'in' file: %v\n", f.Name(), err)
	}

	var eWriter io.Writer
	if len(ekey) != 0 {
		eWriter, err = encryptWriter(out)
		if err != nil {
			log.Fatalf("Error writing %v 'out' file: %v\n", out.Name(), err)
		}
	}

	var gzWriter *gzip.Writer
	if zip {
		if len(ekey) != 0 {
			gzWriter = gzip.NewWriter(eWriter)
		} else {
			gzWriter = gzip.NewWriter(out)
		}
		defer gzWriter.Close()
	}

	var ngWriter *pcapgo.NgWriter
	var writer *pcapgo.Writer
	if ng {
		if zip {
			if newg {
				ngWriter, err = pcapgo.NewNgWriter(gzWriter, ngIn.LinkType())
			} else {
				ngWriter, err = pcapgo.NewNgWriter(gzWriter, in.LinkType())
			}
		} else {
			if newg {
				if len(ekey) != 0 {
					ngWriter, err = pcapgo.NewNgWriter(eWriter, ngIn.LinkType())
				} else {
					ngWriter, err = pcapgo.NewNgWriter(out, ngIn.LinkType())
				}
			} else {
				if len(ekey) != 0 {
					ngWriter, err = pcapgo.NewNgWriter(eWriter, in.LinkType())
				} else {
					ngWriter, err = pcapgo.NewNgWriter(out, in.LinkType())
				}
			}
		}
		if err != nil {
			return fmt.Errorf("error creating file: %v", err)
		}
		defer ngWriter.Flush()
	} else {
		if zip {
			writer = pcapgo.NewWriter(gzWriter)
		} else {
			if len(ekey) != 0 {
				writer = pcapgo.NewWriter(eWriter)
			} else {
				writer = pcapgo.NewWriter(out)
			}
		}
		if newg {
			if err := writer.WriteFileHeader(262144, ngIn.LinkType()); err != nil {
				return fmt.Errorf("error writing file header: %v", err)
			}
		} else {
			if err := writer.WriteFileHeader(in.Snaplen(), in.LinkType()); err != nil {
				return fmt.Errorf("error writing file header: %v", err)
			}
		}
	}

	var packetSource *gopacket.PacketSource
	if newg {
		packetSource = gopacket.NewPacketSource(ngIn, ngIn.LinkType())
	} else {
		packetSource = gopacket.NewPacketSource(in, in.LinkType())
	}
	for {
		packet, err := packetSource.NextPacket()
		if packet == nil {
			break
		}
		if err != nil {
			return err
		}
		if ng {
			err = ngWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		} else {
			err = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		if err != nil {
			return fmt.Errorf("error writing packet to file: %v", err)
		}
	}

	return nil
}

func start(fname, outname string) {
	f, err := os.Open(fname)
	if err != nil {
		log.Fatalf("Error opening %v 'in' file: %v\n", fname, err)
	}
	defer f.Close()

	out, err := os.OpenFile(outname, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatalf("Error opening %v 'out' file: %v\n", outname, err)
	}
	defer out.Close()

	if err := convert(f, out); err != nil {
		log.Fatalf("Error converting pcap file: %v\n", err)
	}
}

func main() {
	var fname string
	var outname string
	var ekeyStr string
	var dkeyStr string

	flag.StringVar(&fname, "f", "", "pcap file to convert")
	flag.StringVar(&outname, "o", "", "output file")
	flag.BoolVar(&zip, "z", false, "set for compressed output")
	flag.BoolVar(&dec, "d", false, "set for decompressed output")
	flag.BoolVar(&ng, "ng", false, "set for pcapng output")
	flag.StringVar(&ekeyStr, "ek", "", "AES key for encryption")
	flag.StringVar(&dkeyStr, "dk", "", "AES key for decryption")
	flag.Parse()

	if fname == "" {
		flag.Usage()
		os.Exit(1)
	}

	if len(ekeyStr) != 0 {
		if len(ekeyStr) != 16 {
			log.Fatalf("Error: Key length must be 16 bytes\n")
		}
		ekey = []byte(ekeyStr)
	}
	if len(dkeyStr) != 0 {
		if len(dkeyStr) != 16 {
			log.Fatalf("Error: Key length must be 16 bytes\n")
		}
		dkey = []byte(dkeyStr)
	}

	if fname[len(fname)-4:] == ".aes" {
		if fname[len(fname)-7:len(fname)-4] == ".gz" {
			if fname[len(fname)-9:len(fname)-7] == "ng" {
				newg = true
			}
		}
	} else if fname[len(fname)-3:] == ".gz" {
		if fname[len(fname)-5:len(fname)-3] == "ng" {
			newg = true
		}
	} else {
		if fname[len(fname)-2:] == "ng" {
			newg = true
		}
	}
	if outname == "" {
		if fname[len(fname)-3:] == ".gz" {
			outname = fname[:len(fname)-3]
		} else {
			outname = fname
		}
		if outname[len(outname)-2:] == "ng" && ng {
			outname = outname[:len(outname)-2]
		}
		if ng {
			outname += "ng"
		}
		if zip {
			outname += ".gz"
		}
	}

	start(fname, outname)

	fmt.Printf("Successfull conversion: %v -> %v\n", fname, outname)
}
