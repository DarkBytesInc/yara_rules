rule Win_Trojan_Tepfer_58
{
strings:
	$a0 = { 558bec83ec3c57535633db031d80104000891dc0114000ff35c0114000e8ee000000890598114000ff35981140008b3dbc104000893de4104000ff35e4104000891d7c104000ff357c1040008b1d1c114000c1eb028d4de089198b4de0894dc8ff75c88b1568104000894415008b4dd4890dc4104000ff35c41040008905c811 }

condition:
	$a0
}

        