rule Win_Spyware_ye_262
{
strings:
	$a0 = { 576a006a006a006a00e8d208000083ecf8e8ca08000068a0c04500586a026a00ff0daac0450050e8800300005f8b783b }

condition:
	$a0
}

        
