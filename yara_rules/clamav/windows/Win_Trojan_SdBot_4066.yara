rule Win_Trojan_SdBot_4066
{
strings:
	$a0 = { 9ad55c5f99b27aea6dced1e4c4b4415c420c8989e7235ff3bfcadf3603c80a3fb0c7d87fd74d2c88985c3949ce37090f28a9767cd7a76cd5d877d3658ad26bd0384e97b417fd9cc0959f1973dd64a48e083aba0a8b74 }

condition:
	$a0
}

        
