rule Js_Trojan_NoClose_1
{
strings:
	$a0 = { 766172206d7973656c663d27687474703a2f2f7777772e6b617261737878782e636f6d2f626c696e67626c696e672f6d696e696d652e68746d6c273b }

condition:
	$a0
}

        