rule Win_Ircbot_Buffy_1
{
strings:
	$a0 = { 9cea36846c43c83d04d9b612b404da046460736448717be0b7911717bf1ff81dfc85105baca02d7c0d1a3b4ef84b9ec6dad8828b394520a82db1dd2eb00d33b0 }

condition:
	$a0
}

        
