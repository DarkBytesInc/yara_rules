rule Win_Trojan_Worm_48
{
strings:
	$a0 = { 524aeeed4934de0d44e5f5a686ce120d5fb4ed78c70e8714b0f59cbf05ca8f03e165fa135e5d11f6d5b86422e3965c0dc3381ace7be03a7c3cb76b2619d2f083d91283491fdd62720ab402cf9b959993 }

condition:
	$a0
}

        
