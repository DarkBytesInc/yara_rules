rule Win_Trojan_SdBot_2395
{
strings:
	$a0 = { 545a63e88ca4a895dad3646536a3b6816130c5384eb99beddaae6eb6da669bdb5269d186864188c51a95159b5454660f0d1525292a3abff33ef73ecf0c687df6fbfbfd7cbd649e7beeff73ef3df7dc73ce3d7796bf7d75fbcc6883a1c0e1dcddb1738a2150d2f9fa1a83c1f0ecb3cfee }

condition:
	$a0
}

        
