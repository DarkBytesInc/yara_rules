rule Win_Trojan_Netbus_42
{
strings:
	$a0 = { 58a75bb2bb950a9dd7bb9122b2d9904b9eff6fe02a1c77044542deb91daac2ded69e356d81c056cad5de598c3bc35e2e680db15b56af6f6aebd79ae1d9a5af72a427bf09a605d6785809f01b382fd3b06072e34d1faf88ba00ac338116b440bedddab701 }

condition:
	$a0
}

        
