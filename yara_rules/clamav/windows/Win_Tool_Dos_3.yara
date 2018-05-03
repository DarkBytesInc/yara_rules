rule Win_Tool_Dos_3
{
strings:
	$a0 = { c8bac10e03d052baa40a52bab50503c28bd805bf098edb8ec033f633ffb90800f3a54b484a79ee8ed88ec3be47 }

condition:
	$a0
}

        
