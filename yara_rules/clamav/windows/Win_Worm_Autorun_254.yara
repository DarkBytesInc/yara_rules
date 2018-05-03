rule Win_Worm_Autorun_254
{
strings:
	$a0 = { 7368656c6c5c6578706c6f72655c636f6d6d616e643d73696c656e74736f66746563682e657865 }

condition:
	$a0
}

        
