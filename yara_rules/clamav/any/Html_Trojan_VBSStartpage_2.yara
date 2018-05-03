rule Html_Trojan_VBSStartpage_2
{
strings:
	$a0 = { 5c72756e736572766963657322202c77696e666f6c646572202620226d6d406d6d2e76627322 }

condition:
	$a0
}

        
