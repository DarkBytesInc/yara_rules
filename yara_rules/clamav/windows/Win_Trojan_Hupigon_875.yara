rule Win_Trojan_Hupigon_875
{
strings:
	$a0 = { 7dac0fe1a0e422ad0561c7a2b9d2d68a05b6a2e80b97d09a414498e39034ee55538ea03a9adcfc2f1c22e4393735459bbd890a36b9c771d9eec129db6f2da70568beea0529719fd7f6a2aadb5190f216c314e3c35a6691c5c616a8a5ce3b47 }

condition:
	$a0
}

        
