rule Win_Trojan_Startpage_515
{
strings:
	$a0 = { 6f667470726f2e646c6c00000000ffffffff0f000000626f6f74696e7374616c6c2e67696600ffffffff090000005c6a6563742e766273000000ffffffff080000006a6563742e76627300000000ffffffff0a000000436f6e6669672e696e69000000000000ffffffff0a000000626174696e6b2e62617400004f50454e00000000ffff }

condition:
	$a0
}

        