rule Win_Trojan_Grunt_2
{
strings:
	$a0 = { e90000e800005d81ed06018db6ca01bf000157a5a48d96d001e89b00b44e8d96c40133c9cd21722db8003d8d96ee01cd2193b43f8d96ca01b90300cd218b86ea018b8e }

condition:
	$a0
}

        
