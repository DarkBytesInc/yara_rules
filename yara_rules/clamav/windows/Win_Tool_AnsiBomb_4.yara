rule Win_Tool_AnsiBomb_4
{
strings:
	$a0 = { bca810b13590a33875d5a9cfa9c53e0dbfe076df2e297018d8b2036ec9e50462cdb31f911321535c }

condition:
	$a0
}

        
