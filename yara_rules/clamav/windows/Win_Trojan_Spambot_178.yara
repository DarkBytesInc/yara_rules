rule Win_Trojan_Spambot_178
{
strings:
	$a0 = { 26e5f90e4de946ce5250b36b69f031f668fe46124630e3f425a0615be61affffffffa3f525018d9f95ac33a3ff7b18bc8ecb42347de6e0e605c219274841cddf4e223af8ffff156a8f5c7b544363dbe99d2951c9e7e19c0417340d2182ffffff3ffdf76fe4890e31db4024c60bbf }

condition:
	$a0
}

        
