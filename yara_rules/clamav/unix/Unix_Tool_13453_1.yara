rule Unix_Tool_13453_1
{
strings:
	$a0 = { eb275e89f731c951b01750cd8031c050b11eb02ef2aa58aab11efec9fe040efec9e2f756b03d50cd80e8d4ffffff }

condition:
	$a0
}

        
