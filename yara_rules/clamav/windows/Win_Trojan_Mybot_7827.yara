rule Win_Trojan_Mybot_7827
{
strings:
	$a0 = { 649a06c26a10480c0615152a4165202c091a452419cb41bb1d19a44200d40bedda5e52d3754b680c3b242c869ad5a8b46f044b538d1b4aa5a96d8f1383161c247abc12ab6b1a17a9ded2de43927799159420b137dddfe377f8508c6bccb97bdfcdcefe4b73399916f3f005e73bc900e574b4bcbb206242595648cbd841 }

condition:
	$a0
}

        