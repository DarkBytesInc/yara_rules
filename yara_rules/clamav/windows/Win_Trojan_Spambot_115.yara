rule Win_Trojan_Spambot_115
{
strings:
	$a0 = { 8d29ffffffff7e679fbcac487539a21b4d02619e0c6a3b1fa26609cf6016e36ed10b512e95aefffff7bfb55f7254a4b654b4a1eb0f0ddf0dd6f10f8509ed76d586690371f849d2afd1df1bc7470f04f1ffff3f01b5ba80a94322212dd882982392e9a02deb057186ffffffff98e7 }

condition:
	$a0
}

        
