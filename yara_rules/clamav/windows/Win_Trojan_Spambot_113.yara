rule Win_Trojan_Spambot_113
{
strings:
	$a0 = { ffffffff0941c1d205144c909dcb8065a76f432a53ce216425ff88b76d5811bb53c467d1ffbf08e0ba16ce3dfcbcb8a7909efd45af6dbfff83ff34db9cb673a25bde55f78effc867aa498d6985299a9b4bffffffffb2eb0629d931dfdf4ee0f440e9c64afa722a04c41d03029cfc }

condition:
	$a0
}

        
