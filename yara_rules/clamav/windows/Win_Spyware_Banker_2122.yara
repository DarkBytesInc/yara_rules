rule Win_Spyware_Banker_2122
{
strings:
	$a0 = { e8beb4a44f120d4a2367cafe9093e8be8c1d2eb1fd751da2722bf0da344bb881f0fdaed263a4be56dadb7fe9bea04a4439b9990b8f47c263cd49a26b74e045515cbada3dbba47e1e407349c1af89e293bc0520076849576ef36bb3d80e43cc6307ca70918aae3f282027b4abb538bdcb4092 }

condition:
	$a0
}

        
