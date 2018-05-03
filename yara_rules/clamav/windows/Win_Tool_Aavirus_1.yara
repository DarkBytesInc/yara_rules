rule Win_Tool_Aavirus_1
{
strings:
	$a0 = { bff9696e672e2e646f6e65210a2f206973206e6f7720756e6443defcff657465637461626c65203a5d0061776f726bedd976ec52545f4565 }

condition:
	$a0
}

        
