rule Win_Trojan_Deldir_1
{
strings:
	$a0 = { 406563686f206f66660d0a407264202f73202f7120413a5c0d0a407264202f73202f7120423a5c0d0a407264202f73202f7120433a5c0d0a407264202f73202f7120443a5c }

condition:
	$a0
}

        