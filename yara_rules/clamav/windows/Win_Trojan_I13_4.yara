rule Win_Trojan_I13_4
{
strings:
	$a0 = { 029078e800005d81ed070150558becc7460200015db904008db6f401f3a48d963902b41acd21b44eb93f008d96ee01 }

condition:
	$a0
}

        
