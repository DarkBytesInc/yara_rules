rule Win_Trojan_SdBot_3685
{
strings:
	$a0 = { 7c95417b316d9ca693c1fa7838ac97ba3c72005a8a022b67ba3dbbb3762abbed250d357263aafee6380cb360fbd5510791aeac512039ba5613407d257fd0d779b597a5fca1028010dc42198586ca }

condition:
	$a0
}

        
