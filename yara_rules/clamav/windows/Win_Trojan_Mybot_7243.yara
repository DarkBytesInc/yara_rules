rule Win_Trojan_Mybot_7243
{
strings:
	$a0 = { 06bf972b49f74a052aa230070caa27d46811506b679eb89c01bfef432a7087c9b6fc75ccde7f041f3783c9bf05f23806f07b4ad2c23c4b1a34a9cb56ce4ea7cdeb6460398f2830b194a4252ed6c6 }

condition:
	$a0
}

        
