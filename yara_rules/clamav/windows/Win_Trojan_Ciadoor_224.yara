rule Win_Trojan_Ciadoor_224
{
strings:
	$a0 = { 45f910999d8d5c2efa91f51be58d257967a25a16abe869c1444ab23c5a88d5fef09b3bec6f9c0804fd07e06ee168c480fd4f490f8d9b2c6dd431abb09b81058f859b640ffbdb5251beecbda386e7361c7de1c9417444c87fbc101c2678b30fc18bd4d2ab }

condition:
	$a0
}

        
