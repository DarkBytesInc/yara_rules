rule Win_Trojan_Mosucker_9
{
strings:
	$a0 = { 2221530118201c201c20a0006001530100000800000030002e0036003000000000000c0000004d0069006e0069004d006f0000000000100000007b009d0022209d003a201920a1007600000000001200000030209d003a20ae001c2018203a203a209d000000100000007c0030002e00360030007c00 }

condition:
	$a0
}

        