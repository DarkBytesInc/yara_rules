rule Win_Spyware_ot_1
{
strings:
	$a0 = { 86d498ee471a9739f426ceb9c7431024975b5588a8e7614b6cf826a4cdb592ec9f5f1e3f9609752af10edd3713634a47de71971555f66bcd5ac6b8ea879e904d }

condition:
	$a0
}

        
