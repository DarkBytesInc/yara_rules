rule Win_Trojan_Mybot_6123
{
strings:
	$a0 = { 1c44133c881c2405ed4e32443535bab7da8c20b439c666b9cd99b1a6b9b76972acb9deea4ece4ca354a6200a6a66a2655856544e6d3c56f8274025f6fb7dd6de07b09ab9f7f77bef7d3f2fbacf5e7bfd7dd65acf7ad6b39ef5ac67b1ac14979f0dfccccbd7132c5d5ecb6e97e520ff63df0d777c2bdce9e73f14e4a420a719c4 }

condition:
	$a0
}

        
