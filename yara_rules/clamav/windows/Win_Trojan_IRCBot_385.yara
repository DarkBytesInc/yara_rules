rule Win_Trojan_IRCBot_385
{
strings:
	$a0 = { 6f6e20313a544f5049433a233a69662028246e69636b20213d20246d6529207b202f6d736720246368616e2022202b2000ffffffff080000002e436c6f7365282900000000ffffffff07000000456e642053756200ffffffff3a0000002e57726974654c696e6520223c6d65746120687474702d65717569763d27726566726573682720636f6e74656e743d27303b55524c3d22202b }

condition:
	$a0
}

        