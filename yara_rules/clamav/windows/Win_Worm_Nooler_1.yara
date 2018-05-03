rule Win_Worm_Nooler_1
{
strings:
	$a0 = { 682ac340008d85f0feffffba03000000e8a67dffff8d45fce87a7dffffc3e99c77ffffebe05b8be55dc300ffffffff1d00000053756d206f6620616c6c20466561 }

condition:
	$a0
}

        
