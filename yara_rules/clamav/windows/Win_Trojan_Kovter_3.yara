rule Win_Trojan_Kovter_3
{
strings:
	$a0 = { ff04245853291db64740008d583f25ff0000008a4c04??0fb6d103d781e2ff00000083f3178bfa03f08a543c??885404??5b4d43291db6474000884c3c?? }

condition:
	$a0
}

        
