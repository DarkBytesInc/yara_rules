rule Win_Trojan_Kerrang_1
{
strings:
	$a0 = { 1d67f4800567f7800506060c6c0600076c0c001e646711c06e07646e04646e046772016a274b657262616666656c79205572676f204b657272616e676121204b657272616e67612121212120 }

condition:
	$a0
}

        