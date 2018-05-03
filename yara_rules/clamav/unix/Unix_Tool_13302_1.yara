rule Unix_Tool_13302_1
{
strings:
	$a0 = { 7c631a7938a004043005fbff7c240b7844deadf2696969697c2903a64e800421 }

condition:
	$a0
}

        
