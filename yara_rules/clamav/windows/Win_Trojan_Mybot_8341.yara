rule Win_Trojan_Mybot_8341
{
strings:
	$a0 = { 925ddfd1a51e782c3d2e4be8d60e6c8138fca057ba38cf1c3391b2d59724353c4da04073a34a49894280b41bcd7e1d00c360d0de4b54b360b71ca2c648c7be37f46831ef74e04fe4f6d787ae8166d3e5 }

condition:
	$a0
}

        
