rule Win_Trojan_VB_536
{
strings:
	$a0 = { 5d200f0cd731235a4e47a038ccfaf3d54664240eddaa69f7ed5265034b7ed76165ad105ee9adb397c61562704bf9d110f6a2b01ce901cf669584b77d3e7caf2ad809b0c11439ef3ccb8e82e8eeacf47403d197feff91b5cd9ebd0f9299beffef }

condition:
	$a0
}

        
