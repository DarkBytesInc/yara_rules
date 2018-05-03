rule Doc_Trojan_Rousted_1
{
strings:
	$a0 = { 456c736549662041442e4c696e657328312c203129203c3e2022274e564322205468656e }

condition:
	$a0
}

        
