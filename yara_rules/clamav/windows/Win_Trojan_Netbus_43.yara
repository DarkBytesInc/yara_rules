rule Win_Trojan_Netbus_43
{
strings:
	$a0 = { f9b49cb82fe24f1c4bd4972f8ebff2a0e9e418bfb37f630fd2a47722f6bbccde5b377663c33c1f476e2e12808f0c32d528ba0dac4198d9af04eb7a0ba21e8fdd52c12cc355c7693a008b681ee0ddf7e0261b3f5001181d2d10f825468c623a881f49f886 }

condition:
	$a0
}

        
