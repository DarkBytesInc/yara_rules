rule Win_Adware_Virtumonde_13
{
strings:
	$a0 = { e7b6db3d0ff367a3b988d1075b38e1bbc20f6b3af7011bea4bc50d38c587613b12b91e423ef667abb516c5056f34ea8e77845e3a45a0f495c5097907ed07202d12cb170390f565a6b9e88f88212915de }

condition:
	$a0
}

        
