rule Win_Trojan_MidInfector_1
{
strings:
	$a0 = { 4d6964496e666563746f72206279204461726b20536c61796572206f66205b5450564f5d20208bf2 }

condition:
	$a0
}

        
