rule Win_Trojan_Agent_32643
{
strings:
	$a0 = { c3372db253abf8a5be64f0109f1570da5aabf8adbe6cf8bdbe6058391981766a706d242f9a81fab99bedba64e26d0dfa11b9cb2556a4bf28736a804211a2f008999bd9839b302c2a112c57ed1fa807ce1060f31065 }

condition:
	$a0
}

        
