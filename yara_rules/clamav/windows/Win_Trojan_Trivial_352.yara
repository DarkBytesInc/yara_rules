rule Win_Trojan_Trivial_352
{
strings:
	$a0 = { b44eba4601b90300cd213d1200eb002e8bbc2101562e03362101b800438bd6cd210000b8023dba9e00cd21b94b00ba0001b440cd21b43ecd21b801438bd6cd21b44fcd2173c9 }

condition:
	$a0
}

        
