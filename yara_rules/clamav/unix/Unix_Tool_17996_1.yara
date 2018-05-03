rule Unix_Tool_17996_1
{
strings:
	$a0 = { 2418f99a0710ffff2818ffff27e810012508abcd3c090000352900003c0b01e0356b78278d0affff01496026ad0cffff2508fffc154bfffb01e07827 }

condition:
	$a0
}

        
