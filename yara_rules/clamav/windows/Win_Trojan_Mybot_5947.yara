rule Win_Trojan_Mybot_5947
{
strings:
	$a0 = { 66a2db0ff1dbcd82240c587fedf68d51c3b4b6de0141902f226c511400eff7a161d5e8aeead5d8b4d7b3372da34361635be6fc29b39cd0d0bc529df9749ac7635c7e3b3b10eaec98ff3ba4610f06ffccffbf124cb3b1e5ee17c1a6aed64d9f7f158054aee5de208b }

condition:
	$a0
}

        
