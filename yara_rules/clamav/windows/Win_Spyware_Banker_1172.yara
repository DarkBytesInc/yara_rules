rule Win_Spyware_Banker_1172
{
strings:
	$a0 = { 02a4d06c7045629de086467700fa3babcd87f2c1ae81641a65de9f671823dbd7b74f81c0b27b1c352a7b03eac45f8c391c8e0687bee8ba67d5b410dca038f9cf1b8a67fa8e3ae1f222f399069659fea44c86d1db81e8df4b69ef }

condition:
	$a0
}

        
