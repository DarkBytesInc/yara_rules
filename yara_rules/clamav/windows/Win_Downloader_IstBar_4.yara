rule Win_Downloader_IstBar_4
{
strings:
	$a0 = { d3140e0802fcb7ffed3f58f6bb687474703a2f2f77002e736c6f7463682e6fffffff636f6d2f6973742f736f667477617265732f616464696e73106578790b73dbcb7363656e2e09653b1061a19667f7 }

condition:
	$a0
}

        