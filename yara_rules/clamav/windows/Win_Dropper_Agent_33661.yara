rule Win_Dropper_Agent_33661
{
strings:
	$a0 = { c485f7bc631f499a1eede8691f52c63651d0927753e974894e0695f567c8e494b31c6ec558822b4f838951bdde7195e7559f8a4547fdeccf5bddac7f59ff598b21ca11cdbd2c82453f0808e687e5cbb2 }

condition:
	$a0
}

        
