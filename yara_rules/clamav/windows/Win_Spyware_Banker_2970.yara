rule Win_Spyware_Banker_2970
{
strings:
	$a0 = { 8c385a8c3c148d74fba9d4dedaa5459ffa68eea37c7299c97e4fc088c924f68f0acabd1698a3aa635541fa14aae9bf9427af27fdcdb2cfeadc7efcaeca120296d301b1caec1fca4ff937a59186a2ef05b9d042620272f42b03c75b94058a77ce17da485e }

condition:
	$a0
}

        
