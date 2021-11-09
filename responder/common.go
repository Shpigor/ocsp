package main

type KeyConfig struct {
	KeyBits  int
	FilePath string
	Clients  []ClientEntry
}

type ClientEntry struct {
	Dns string
	Ip  string
}
