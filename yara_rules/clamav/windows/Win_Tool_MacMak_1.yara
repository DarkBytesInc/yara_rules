rule Win_Tool_MacMak_1
{
strings:
	$a0 = { 350001010d004d614b726f204d614b65722b2b00030d000080040e0000800538047800d70a }

condition:
	$a0
}

        
