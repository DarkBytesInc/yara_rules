rule Doc_Trojan_Boombastic_1
{
strings:
	$a0 = { 696f6e3a3d4461746e616d65242c204e616d653a3d224175746f4f70656e222c2054 }
	$a1 = { 67616e697a657220436f70793a3d312c20536f757263653a3d576f726442617369632e5b44656661756c74446972245d283229202b20225c4e4f524d414c2e444f54222c2044657374696e6174696f6e3a3d4461746e616d65242c204e616d653a3d224175746f45786563222c2054 }

condition:
	$a0 and $a1
}

        