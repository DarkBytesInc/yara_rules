rule Win_Trojan_SdBot_3882
{
strings:
	$a0 = { 56951b69f005c8ce6c88129eccf06f44066dcf246fa4b246ae01a99604bc7f9de444248c499c1df9b46dcb9811e432fe2ac3c53c8ad001c97aa04f9cddd389c74a823f02e41107c0d690e1610bc3661979eb5b98563ceabccf6cce99 }

condition:
	$a0
}

        
