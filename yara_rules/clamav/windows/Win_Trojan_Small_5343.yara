rule Win_Trojan_Small_5343
{
strings:
	$a0 = { 1fb06024a62b01e2ba6b73b2d22acca7c77e7ccd5a6be6a4b50e9c820a3b7392ba1fcca722398ca7cad35b934a3b0f6352f24ff41db0f0835a08579cb14e88958ad0a19e554faef1c1fc0750b50b73d36e2f640e703b8cfecf }

condition:
	$a0
}

        
