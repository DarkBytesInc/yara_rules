rule Win_Trojan_G_Door_5
{
strings:
	$a0 = { b210480a685bf241e48b2ffeed69eb2f7ee959cfb7ffd479f4a212fcdf116243244ab010abb5cf156c4a0eef4499533cd39db8bb62dff3b91640f1d2daeadb0c38927b10e0e6140dbef3e399366127c5ec44583c0dec4aca724c9b72cdce540e7c9b96ece15987da75d04b5a6b1bc30b3dcbe1726881d940a2ffd6 }

condition:
	$a0
}

        
