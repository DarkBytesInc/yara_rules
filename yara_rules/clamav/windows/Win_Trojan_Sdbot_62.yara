rule Win_Trojan_Sdbot_62
{
strings:
	$a0 = { e1735e0dbec1338636cc8f06da52a53348dc77b3f756af7e63b9727a000f7430fdd7e52c218f7516c3f272b752fa6eaf1dd049df954aab78270b168fb1fee72e7eb17dcd00de5bdb62e3bd0a7a0bf5c9119d293244dacfeb711cbcecdf1dbce564454107fa390a62f4d9ba5f8c2dac88f73ff8ca3b343b77 }

condition:
	$a0
}

        
