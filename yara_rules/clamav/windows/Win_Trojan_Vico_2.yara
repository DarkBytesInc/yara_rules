rule Win_Trojan_Vico_2
{
strings:
	$a0 = { 018a853a00a200018b853b00a301018cc889853000b84b0103c789852e00b8fe002d38002bc7898538009a5802 }

condition:
	$a0
}

        
