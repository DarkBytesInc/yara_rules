rule Win_Trojan_Small_3742
{
strings:
	$a0 = { a21f91feb91a52171096653f0aedf7ff0cff7512fa97e2e62b9a8dfe3c5ba6fd2ebba5fdcf9f9d3ebaf6eb5b15f0505511ff8d0eba97f706b9acc50efa97ddfdcfd39d3eba227e69ba01b15424978c140ea7cdfe3e57023145d4bd0efa97e3fd911c4e73dfed8cd63a13befd160c9654b96e0e }

condition:
	$a0
}

        
