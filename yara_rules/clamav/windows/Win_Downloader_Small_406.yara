rule Win_Downloader_Small_406
{
strings:
	$a0 = { c5e17876d4492048ff80f35c3c00e27d8c536f66747700d82c006172655c4d6963726f735c57696e646f77735c436b01702d75726e7456657273696f6e15e75b2054727573dc16b48b20507669645c80744a9875626c69f071712e7368674461740000b809616261733000656570656c6b6a65646b6e6864 }

condition:
	$a0
}

        