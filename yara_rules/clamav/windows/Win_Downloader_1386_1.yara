rule Win_Downloader_1386_1
{
strings:
	$a0 = { e1990a2b7c06a36ddf84ef3fd36b80d107c07c6966f3e580cedf2f016c01aad83d38708ddbb43cdab2d03626820e4a1a2ba7405d8722ebb9d111d1b9bacbbf1670c2632a419a4f64a0dd2fb9317816b1f02297533abea4ffc7d5ce710e487d81e506f0 }

condition:
	$a0
}

        
