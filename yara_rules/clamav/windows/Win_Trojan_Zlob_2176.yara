rule Win_Trojan_Zlob_2176
{
strings:
	$a0 = { 566964656f204100637469760065582000536f6c00757400696f6e00 }
	$a1 = { 756c6c736f667420496e7374 }

condition:
	$a0 and $a1
}

        
