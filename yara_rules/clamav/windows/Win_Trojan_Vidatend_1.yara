rule Win_Trojan_Vidatend_1
{
strings:
	$a0 = { 8b55f8b840794100e848f0feff8d45f450b9a8584100bacb5841008b03e8c3eeffff8b55f4b844794100e826f0feff8d45f050b9e0584100baf55841008b03e8a1eeffff8b55f0b848794100e804f0feff8d55ecb801000000e8b7f1ffff }

condition:
	$a0
}

        
