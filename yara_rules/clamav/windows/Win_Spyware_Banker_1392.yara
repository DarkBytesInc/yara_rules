rule Win_Spyware_Banker_1392
{
strings:
	$a0 = { f8a4023179ac4e87f0ef79d2b7fc7b7b24e53cd82ae559832eb2160087a61ff75a0f107bc5dc502b2312d21e7556959490f1a29d86356e3a5271633b5af38e8a49aee1e9 }

condition:
	$a0
}

        
