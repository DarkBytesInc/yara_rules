rule Win_Trojan_Hupigon_133
{
strings:
	$a0 = { 67d04ad2382bc1dc8909de0ed4e38c9689c6ce3dca16c2cd475564fa5f1f5839e2b0e1d2bdc5429ed69ee64047185dbf8ec4bf9efa29c4a5537cfa5cd02cb25edef81320285ea371064f855b098cdf436fa8fd82c0a669b50c8872d33b267701beaae35a8ce86783f36f6e5864de }

condition:
	$a0
}

        
