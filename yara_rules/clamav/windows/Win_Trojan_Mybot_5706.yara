rule Win_Trojan_Mybot_5706
{
strings:
	$a0 = { 1f582e28af4a8efff47e4c42e8eb4294d1f176f9fbede15ff86372da17567e5a27cc7a8ddc34b8e8f4d148a42bdd346394d4b0addcf90e4cca433c49f176695f92c5b6e09595f1a3a474856121a85fb4b62aa69154d697a34b17 }

condition:
	$a0
}

        
