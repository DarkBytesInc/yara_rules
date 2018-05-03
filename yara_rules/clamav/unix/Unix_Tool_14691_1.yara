rule Unix_Tool_14691_1
{
strings:
	$a0 = { eb1231c95e565fb1158a06fec8880646e2f7ffe7e8e9ffffff32c132ca5269307469016930636a6f8ae4b10cce81 }

condition:
	$a0
}

        
