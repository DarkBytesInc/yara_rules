rule Win_Trojan_Bancos_1880
{
strings:
	$a0 = { f8c2c38e8bfe8bbe11a5011d77a9662ba1b60e0c0f3679e9ad52034a746c159cd9f9963d999422227de445a39feb5b72cfdeed1e8a4246219f485ba118c038867cb395dd9891 }

condition:
	$a0
}

        
