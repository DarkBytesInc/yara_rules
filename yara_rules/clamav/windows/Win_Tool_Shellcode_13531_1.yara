rule Win_Tool_Shellcode_13531_1
{
strings:
	$a0 = { 83c4ec33c05050506a066a016a02b8 }
	$a1 = { ffd08bd833c08945f4b002668945f066c745f2e5c56a108d55f05253b8 }
	$a2 = { ffd06a0153b8 }
	$a3 = { ffd033c0505053b8 }
	$a4 = { ffd08bd8ba }
	$a5 = { 536af6ffd2536af5ffd2536af4ffd2c745fb41636d648d45fc50b8 }
	$a6 = { ffd0 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6
}

        
