rule Win_Trojan_Mybot_8476
{
strings:
	$a0 = { de442864da926b179db703af0d08ecfadfca0850e0cc9f626460587f7d8e4c6e3fee646b9bdebab658acab7a3c906823fb4946f749268075ff8d0fdc565d4cdbd0295d36988c33bbaa1ff665858ff1f08c98034fda }

condition:
	$a0
}

        
