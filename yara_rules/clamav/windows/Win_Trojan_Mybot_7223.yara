rule Win_Trojan_Mybot_7223
{
strings:
	$a0 = { c9b43218827d0921cb9344929f5ea08464f1e4419cb8219117bf4264114538db27ad27baf3b8ac5f339f23607a9c547bd83da285fd4e8914ff3ca57edc205f74f1d6dc1875fdefbe5c81d041e0ff }

condition:
	$a0
}

        
