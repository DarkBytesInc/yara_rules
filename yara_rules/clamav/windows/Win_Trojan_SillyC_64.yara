rule Win_Trojan_SillyC_64
{
strings:
	$a0 = { 010021b90300fc33db8bbf010183c703578db5a101bf0001f3a45fb920008d959b01b44ecd21720ee81000b44fcd217205e80700ebf5bb0001ffe3b8023dba9e00cd21 }

condition:
	$a0
}

        
