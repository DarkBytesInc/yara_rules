rule Win_Trojan_Wazzu_17
{
strings:
	$a0 = { 690a46696c654d6163726f240c6903414243736800076a015c076903414243736700076a093a4175746f4f70656e64690a476c6f624d6163726f240c6a0f476c6f62616c3a4175746f4f70656e64690a4d6163726f46696c65240c67af800567098005678e810567b880056c00000606126c }

condition:
	$a0
}

        