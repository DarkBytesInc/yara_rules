rule Win_Trojan_FakeAV_109
{
strings:
	$a0 = { 558bec81ecd4020000b8f5ff000089c1898d40fdffff898dc4fdffff89f1c785d0fdffffe0000000c785d1fdffffe29030c0b801000000018540fdffff0185c4fdffff35f60f400083f0013185c4fdffff8b85c4fdffff8b3889bdc8fdffff8db5d0fdffff5631f6568d45f4506a048db5c8fdffff568d85c8fdffff50e88afe }

condition:
	$a0
}

        
