rule Win_Trojan_BloodyWarrior_1
{
strings:
	$a0 = { 3d4036900e1f81772a40369081772e40369081773140369081773940369081773b403690fb }

condition:
	$a0
}

        
