rule Win_Trojan__0739_0001_001_1
{
strings:
	$a0 = { 33c933d2cd21b04086e0b905008d965f00cd21ba024233c933c092cd21e81000e80800c3b8023d }

condition:
	$a0
}

        
