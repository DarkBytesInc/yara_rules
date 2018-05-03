rule Win_Worm_Rokiwobi_1
{
strings:
	$a0 = { bac8aa4000e9790b00008b8d70ffffff5168448c4000ffd685c0750abab4ab4000e95d0b00008b9570ffffff5268548c4000ffd685c0750abac0ab4000 }

condition:
	$a0
}

        
