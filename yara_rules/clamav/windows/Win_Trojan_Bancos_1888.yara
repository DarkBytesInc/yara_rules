rule Win_Trojan_Bancos_1888
{
strings:
	$a0 = { 8dd183a3a22e046126ae18132541e8b1abbda0f8197d51593a3cc4e6a59f47727f99153b840ad29539067f3253607e9f1bad49dc5c2d80c275593b0fde3a4b9ce634527aa005 }

condition:
	$a0
}

        
