rule Win_Trojan_Hupigon_530
{
strings:
	$a0 = { f2c36fd422f08220a94a7073f354a6f9b3c7d49273e6a059834874b443b04d124149e2f5903b4585776cd813e0a9bdada8b4145b5cb94f670a202eb5d78710b1c3480d9cff9fec4b754b50065e47 }

condition:
	$a0
}

        