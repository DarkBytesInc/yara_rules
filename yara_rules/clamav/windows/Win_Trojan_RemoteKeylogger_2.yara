rule Win_Trojan_RemoteKeylogger_2
{
strings:
	$a0 = { 40007800000082000000890000008a000000000000000000000000000000000000006b6579636c69656e74006d6173746572000050726f6a65637431000070010000380000000000000000000000d0000000d800000000000000f80000004800000000000000400100004d010000620100000000000096d88d2445bbcf119abc0080c7e7 }

condition:
	$a0
}

        