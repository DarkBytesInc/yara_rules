rule Win_Trojan_Rukap_66
{
strings:
	$a0 = { d2a784fa25c3c8404b5dc3428052c95e033026e46bb2b06d0c2854bc1a044977de42c2937f1447d3e2ce1d0fd683f538bfb2c8ce08bed3e8f2b46d39db69e9779651a4248bb72d82 }

condition:
	$a0
}

        
