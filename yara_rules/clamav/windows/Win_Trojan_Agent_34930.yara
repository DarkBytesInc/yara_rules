rule Win_Trojan_Agent_34930
{
strings:
	$a0 = { b12fa046e1be7feaad0801ecfb3f77fdf63a34bdbdc4ab85447864fad027ceaf4442cd7b2c4015c9d50e18cef328c2c29742cb4ffd2306f9880d68ec947fd59e29ad6f9ed62785a4d2bfaf9e493719c8e912a1d19de4f763716c }

condition:
	$a0
}

        
