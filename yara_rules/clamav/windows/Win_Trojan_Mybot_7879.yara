rule Win_Trojan_Mybot_7879
{
strings:
	$a0 = { 7f5f2edc569c05bc9f7a2f09b4412a86b38f0f2cbdd5d3aaf88cc56b0686f9ddacc810bf9f6254c559d6bd3b70a09484037a8d4bc3d526fe9cf7321e680143278f386d08ac584f65fc56379d776406b9d70b47fa2d46f289951d412b2eb24865991bea865a2c374c60bd26b67b2d82c1184c5215e9b71b55caeabdf7b3ff1db7 }

condition:
	$a0
}

        