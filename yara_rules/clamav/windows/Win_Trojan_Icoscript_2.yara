rule Win_Trojan_Icoscript_2
{
strings:
	$a0 = { 8a4c37018a1437c0f90480e10383c604c0e2020aca880c188a4c37fe8a5437fd40c0f90280e10fc0e2040aca880c188a5437fe8a4c37ff4080e13fc0e2060aca880c188b4d0c408d51fc3bf27c }

condition:
	$a0
}

        
