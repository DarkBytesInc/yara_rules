rule Win_Worm_Iksmas_5
{
strings:
	$a0 = { 8d427ebed4284000498d5d0881c2172500008d4b2fb9ce1040008d4506890b4f5e8d }

condition:
	$a0
}

        
