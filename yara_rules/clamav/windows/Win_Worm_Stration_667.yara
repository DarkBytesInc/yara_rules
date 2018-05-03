rule Win_Worm_Stration_667
{
strings:
	$a0 = { ca70736f79547d722cfc17f67870791cbf212b3624352c6b9829f15b5cb8dbf156eafa74c0de9f00b8a4ff172ed9ae99088e98b0958f88ba8e9999fcebffffbf287a7e3f523e3f236961610d00 }

condition:
	$a0
}

        
