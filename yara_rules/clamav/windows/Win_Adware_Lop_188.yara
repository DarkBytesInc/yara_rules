rule Win_Adware_Lop_188
{
strings:
	$a0 = { aff94da8652baa067f1731c67860eb9208180b452261c118404c31f5c6bd3a6366cb27acf357925252dc5deb6d77a4e79f163b720d4870f829013653 }

condition:
	$a0
}

        
