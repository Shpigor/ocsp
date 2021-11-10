package main

type KeyConfig struct {
	KeyBits       int
	IndexFilePath string
	Clients       []ClientEntry
}

type ClientEntry struct {
	Dns      string
	Ip       string
	FilePath string
}
