rule Win_Spyware_Banker_2715
{
strings:
	$a0 = { 37ef48ae089a5220318519d89b95fc9778e8e7861b2632ab92b5d2cccffe7eab08f56cfc6f7a36aea73285ce5502d89368456162ce0ada18c8140f88e150b7c599b5ae840fdf83717e52eab23433 }

condition:
	$a0
}

        
