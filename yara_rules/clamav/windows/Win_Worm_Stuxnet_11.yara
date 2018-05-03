rule Win_Worm_Stuxnet_11
{
strings:
	$a0 = { 8b44240883e80074144875118b4424046a01a31c400010e8b70100005933c0c20c006a00ff150830 }

condition:
	$a0
}

        
