rule Win_Trojan_Python_1
{
strings:
	$a0 = { 050005941f05945eb92f022e8b142e31541546464975f7558a1b68a49605b94a948b540b8b53ca847a6490366bbcaf }

condition:
	$a0
}

        
