rule Win_Trojan_Asmodeous_6
{
strings:
	$a0 = { 3a00a33200c70634001e040316900389163800b440b97203ba9003ff1614003bc17281b8024233 }

condition:
	$a0
}

        
