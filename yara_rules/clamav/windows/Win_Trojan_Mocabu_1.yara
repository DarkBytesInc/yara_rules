rule Win_Trojan_Mocabu_1
{
strings:
	$a0 = { 792072610d626f77737f4d76b8bdee27af79832c7579175585d85dc3738a62eb6e6f74109a65dbc80a8f26ed6424a1e88dda73e7c52e657843436c5b066057 }

condition:
	$a0
}

        
