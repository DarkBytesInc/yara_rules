rule Win_Trojan_Bancos_1056
{
strings:
	$a0 = { db3b02247bb6547b039fcc88ae2a18cddd80473e09b2a9d6cba2a454e4cff52d050905c570caec6f4e68a4c4d72099d4c2ee093e2bc762981e2b90c0007bfcac733cdeb588e82c8494a2ec2cebd15887456af9630b8e32bf }

condition:
	$a0
}

        
