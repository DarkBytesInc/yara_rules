rule Win_Trojan_Hupigon_56
{
strings:
	$a0 = { 7dc4b23704dfdb6855e7da97800c8a23b1ac7ffcd227ad98ded9e505a82ec3541ec892f1f6172aa5f2e8f5208633112fdb35e93cfeda9b1a0cbf7e3b218db98f45dfa54f0cb97a83245fd8563dcb039f525a1bd0b2dbbfb2bd294f0e9446ab3da8963c8dfb17c185eb593c49872dc7e5a30f7a3352ca0f08 }

condition:
	$a0
}

        
