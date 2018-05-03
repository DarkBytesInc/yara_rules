rule Doc_Trojan_Nutshell_1
{
strings:
	$a0 = { 496620646628642822b6c9c2c588847db7c1b97ccabcbec6b8b7c9c783b2ba7dc7bcc8c7c87dc3c3c97cbac6ba22292c20736176617329203d2054727565205468656e }

condition:
	$a0
}

        
