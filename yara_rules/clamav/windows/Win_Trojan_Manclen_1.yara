rule Win_Trojan_Manclen_1
{
strings:
	$a0 = { 4d41444e4553532e57726974654c696e6520223c212d2d4e5941524c4154484f5445502d2d3e22 }
	$a1 = { 445245414d494e472e57726974654c696e6520226e313d2f6463632073656e6420246e69636b20433a5c6d6972635c486f775f546f5f4d616e75616c5f436c65616e5f4d79446f6f6d2e68746d207d22 }

condition:
	$a0 and $a1
}

        