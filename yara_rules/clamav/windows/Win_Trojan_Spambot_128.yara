rule Win_Trojan_Spambot_128
{
strings:
	$a0 = { b6d835897ffd03fcc7dbd710c8878bafa534a12fec638422a5ffffffff5085f035930429c94cecc4121e831d59f1f4410a52b954edf6f92a216ffc7d72ffffffff66df4ad1ccb6102b3995770d32f1050e477ec181544773a0220d0d55bf78b7ebffffffffe462230884d4ce7477 }

condition:
	$a0
}

        
