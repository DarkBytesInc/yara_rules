rule Win_Trojan_Hackdef_4
{
strings:
	$a0 = { 1228fa2024f16df166e6d9cd1d166141aee0eb071f5fadb062fce047136dd6d72faf7eed4663f2be1ee922a8dd0c5b141116c7bec4f12d9573b784faaec1db33b905208704202a04faf85792ef22bd0f49bd35034cc6842b53ee0c4de6cef10c1f273d51588cdc6a95f0267a782e }

condition:
	$a0
}

        
