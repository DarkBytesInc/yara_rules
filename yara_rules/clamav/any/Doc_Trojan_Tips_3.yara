rule Doc_Trojan_Tips_3
{
strings:
	$a0 = { 696c65537472696e672822433a5c4d6963726f732e496e69222c20224d6163726f53657474696e6773222c205f }
	$a1 = { 2e4c6162656c732833292e54657874203d2022446f6e27742053706974206f6e20796f75722073656c6622 }

condition:
	$a0 and $a1
}

        