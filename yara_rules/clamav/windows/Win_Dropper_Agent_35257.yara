rule Win_Dropper_Agent_35257
{
strings:
	$a0 = { d0927753e974894e0695f567c8e494b31c6ec558822b4f838951bdde7195e7559f8a4547fdeccf5bddac7f59ff598b21ca11cdbd2c82453f0808e687e5cbb2e792cac1eb20cd7d8785c215757c2ab525 }

condition:
	$a0
}

        
