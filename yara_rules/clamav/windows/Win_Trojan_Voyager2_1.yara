rule Win_Trojan_Voyager2_1
{
strings:
	$a0 = { 01b97c001e81373b1483c304e2f7d0025b56546d61675e66325d1b7679207f75766f49344e2ed314005dbaf92b013dac3030f6353d0e }

condition:
	$a0
}

        
