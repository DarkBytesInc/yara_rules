rule Win_Trojan_Warin_1
{
strings:
	$a0 = { 069e326801da8a0a934e81838aa546829a2803da8c7340943028c65340a8a0ffd905c01288ff8f07d70a1204001a01004200ff035e0000000205005465787431000204c0030000ff0f1d010b240049206b6e6f77207768617420796f7520646964206c6173742073756d6d6572 }

condition:
	$a0
}

        