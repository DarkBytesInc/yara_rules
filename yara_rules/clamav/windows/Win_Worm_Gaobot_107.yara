rule Win_Worm_Gaobot_107
{
strings:
	$a0 = { 4f494e6c267f4f4e47c65fe9660c0b491333353307160afcff49524328307825382e3858682929fb63c1181d8d75e13a61 }

condition:
	$a0
}

        
