rule Win_Trojan_Anra_1
{
strings:
	$a0 = { b9dcea4500ba4ceb45008bc6e8d464ffff6a006854eb4500e8689ffaff6aff6868eb45008d55fc8b03e8eb14ffff8b45fce8ef7efaff50e8419ffaff6aff688ceb45008d55f88b03e8cc14ffff8b45f8e8d07efaff50e8229ffaff6aff68b0eb45008d55f48b03e8ad14ffff8b45f4e8b17efaff50e8039ffaff }

condition:
	$a0
}

        
