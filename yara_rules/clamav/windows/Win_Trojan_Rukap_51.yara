rule Win_Trojan_Rukap_51
{
strings:
	$a0 = { 75e38099ae6fcf4a7ac5c33aa4a6c0515fa937e89c1c1ee9526afd2b303e582b8dbc13ea796efe905c10c1d3125e62cba7ab6e5c94d5536e34868d34c4237bb9578e4dd8201dfb79f906cb3537222db52547fa0e026b42ec7e }

condition:
	$a0
}

        
