rule Win_Trojan_Mybot_5716
{
strings:
	$a0 = { cfe3a9d620fd6e03bc46eb3132a9c8b5caf1d6e73917210df61ecd02164a5cf1284f0e7792a7ee80247360edc46a3770af3585376122ade13d3bdb04e62904744e14ff325ff1cbc6e3213d32f871b7a4bebe1ce8c822256729ee }

condition:
	$a0
}

        
