rule Win_Proxy_Ranky_59
{
strings:
	$a0 = { 9d706950d9b511ce68a0426935341e10f4e0f6b28ac6d66af0b338a36c716bafc79f6ba804a73b7560476a12866ee6c74886b12c1c412a1a227fba812fcf6a2fbe4dbc3ba3c2b8b0bffa6c4b8cc2e50956e09b3ea41aee533a60b873082ffa40 }

condition:
	$a0
}

        
