rule Win_Trojan_Small_3906
{
strings:
	$a0 = { 1e2f98e308b46e27105f862e01e34aa78d5efcab67bde3fe8b2397668e4cfbb35dc986a21eaf97e308af85b8586fc6a393ae962e5d83b20d09c9860d0cc9860d09c9d6f45a5e9c5f1a9f8628c9e8cac724d499a21eb796e30826 }

condition:
	$a0
}

        
