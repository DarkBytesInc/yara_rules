rule Win_Trojan_IRCBot_281
{
strings:
	$a0 = { 9c4616fa50f920317f63b9223b07c1c01bd8899258afe74de9f500d94667ec2bc27c5693f44eac98f6d7825a7978edf2a4bbbd2f14bcb6985bcfa66093224c66bbd8997bbe2f70bf59884d4965d5bb51 }

condition:
	$a0
}

        
