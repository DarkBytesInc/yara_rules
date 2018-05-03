rule Win_Worm_Bomerang_1
{
strings:
	$a0 = { a9fba962a96081e4b65d7bebfb3b21ec5aa9ec56232c07515555cc2b968e12aad6d1216f557d3fc0aef3f821fc962968b8557d2b94c4f0c3dadecdf0f1f5f3fda97ff8a944ff27ee975623b2f9a97df82714e5515555fd23fc6427fc721751a9 }

condition:
	$a0
}

        
