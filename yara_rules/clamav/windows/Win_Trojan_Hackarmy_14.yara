rule Win_Trojan_Hackarmy_14
{
strings:
	$a0 = { 63513634855347a60e01505249564d5347c04e4f7954204345ce0a4b0755539752034a4fdfdd3c416f54c05155f5bd0a6d1c4afd4f8d0b457298cf87a76b0a00 }

condition:
	$a0
}

        