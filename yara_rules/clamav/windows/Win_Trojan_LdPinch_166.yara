rule Win_Trojan_LdPinch_166
{
strings:
	$a0 = { 2dab1342d143d79fa4bf6f01f34387385a0e7fa9135787355aafd13782c8fa685a368b373906a660d1d26442569ab4a0bbbcde927fc3b860a54cd03339a8a760d1d2646a584d2a8b34fb8660d14302a98a1cd9a9134b87355aaf06a4d1bf789f16c6879c2ebc8760d143ed60bb43ef60d54387ed54437b9f2e137815c1bcf26cbb43ed603964a660d10bd7ed54437b9f2e13ed60 }

condition:
	$a0
}

        