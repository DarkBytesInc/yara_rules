rule Win_Trojan_Tepfer_27
{
strings:
	$a0 = { 68fc3f40008304240468143140005f83c7928b3fc1e7108bcc8d673c588be103f883c71d33c9330f84c9761a5f51b01c2ac87e0a581c7c7705e9b6feffffb855304000ff50ff6a7c59e2fefa00000091581a003a0000000afefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe }

condition:
	$a0
}

        
