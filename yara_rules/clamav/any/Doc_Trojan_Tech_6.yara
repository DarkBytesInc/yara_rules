rule Doc_Trojan_Tech_6
{
strings:
	$a0 = { 446f626a2e5642436f6d706f6e656e74732e496d706f7274202822633a5c6c6f672e3338362229 }

condition:
	$a0
}

        
