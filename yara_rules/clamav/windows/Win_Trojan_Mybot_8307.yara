rule Win_Trojan_Mybot_8307
{
strings:
	$a0 = { 8e18e487eeddf96845c212574d4a7ef43c6b9aa715ce1cf5dae1efb8b6a122036d77aa54b1487e2be2af8131a3fa07cf4b7bb8e1ff0d58949c018238a66027e9fda8b54859e9f24bb05f006f40e55ba4acc9292f0fb8a73f35b2f9f3e26b79231b1b7b24 }

condition:
	$a0
}

        
