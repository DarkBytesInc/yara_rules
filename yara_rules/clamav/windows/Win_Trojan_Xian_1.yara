rule Win_Trojan_Xian_1
{
strings:
	$a0 = { 77428b3e03018945082d0300050f028b3e0301894506b440b97d078b16030183c200cd2172 }

condition:
	$a0
}

        
