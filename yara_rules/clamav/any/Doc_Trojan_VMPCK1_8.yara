rule Doc_Trojan_VMPCK1_8
{
strings:
	$a0 = { 6374697665446f63756d656e742e564250726f6a6563742e5642436f6d706f6e656e74732e4974656d282242756861776522292e4e616d65203c3e202242756861776522205468656e204948617465596f75203d2054727565 }

condition:
	$a0
}

        