rule Win_Downloader_864_1
{
strings:
	$a0 = { e5a597067b49b1cec95de6cfc5c3c2c9c6e2e8afa47eb050caf864e1246c53137d7e32e6457909db03391cb26cbbc97bbb101ee8e9aa6d49bb47541cac41018ff6e90c0ec23b21bee25fa170ea3ac5025adc02bde88ca587b0cd869e2f29776a04f066273b9cf5b259f839c26cf2de9e5653eeaeaa568c7ddbe8b9a3 }

condition:
	$a0
}

        
