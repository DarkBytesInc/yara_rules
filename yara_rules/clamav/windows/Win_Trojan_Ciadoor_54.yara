rule Win_Trojan_Ciadoor_54
{
strings:
	$a0 = { 6e82ceee2272d1f0ca8910a44496662390c4b574aba5a7d505ff1eb83ef78901f8e98774d9563aa2519caa3460bb64e15c91ea1eff4fae97d9e8f7203f133d773ecef030018e796a02309cbe56766c3d4e1b3e1012624bafe6 }

condition:
	$a0
}

        
