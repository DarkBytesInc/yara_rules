rule Win_Trojan_Spambot_84
{
strings:
	$a0 = { 175e47d481152334b7d0b840feffffff235fa192d04f8fed464231bd72a5e50f5d07bfb937e30f4c376bee84154c872dfeff3ee30b377382a8fe536e576a3a257bbdc1ffffffffdb592c0c9c5e9900a3bacc655d46777d417eea381a7688dc4cfc8114a0a6eeff7ff1ffa2081647 }

condition:
	$a0
}

        
