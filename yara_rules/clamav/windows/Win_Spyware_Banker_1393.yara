rule Win_Spyware_Banker_1393
{
strings:
	$a0 = { a51f74318c8eca43e1f74f01ae81e4d65064832102fa98c0602e4fe3c52e969f3dbc3613707de38f025699eadd26c0b6bcc9b96a2a10071a1e8799b05fd453e51e8263a3 }

condition:
	$a0
}

        
