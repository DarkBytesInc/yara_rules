rule Win_Trojan_Hupigon_823
{
strings:
	$a0 = { 5a2b3ed3bbb94c685c3970cc814bdecafc8b1a8ad89d3fbd719ba9157d749ef571299a6ca203aee16d13028d40e94d4089c424a0e90eafc24e0b4a3698fbc3f70e4d842bdbe1146a561085042a5a51a6643108558e3e34e7bcae162cf469f1 }

condition:
	$a0
}

        
