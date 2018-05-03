rule Html_Trojan_Unicode122_224_9_35_1
{
strings:
	$a0 = { 3100320032002e003200320034002e0039002e00330035 }

condition:
	$a0
}

        
