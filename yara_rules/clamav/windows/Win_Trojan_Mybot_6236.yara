rule Win_Trojan_Mybot_6236
{
strings:
	$a0 = { adfd45b102646b97102f89e1a35329733fb9eed97ea34001dd5d12110965b0cd9dac3be201c8a431fe93f1b1ce2b2d8112cb6c10722f812c58474a6db922754a637e7ad56799c5ec0d73fccdf3612be1e51634cf08734a5b13d1dbbdc49e53fbf9ef92ff39a1f7d954e4f0f3038eac1c093f359c5d0f74781b6a72560d6146ed2733758849e2c0e4bd6b0cc7 }

condition:
	$a0
}

        