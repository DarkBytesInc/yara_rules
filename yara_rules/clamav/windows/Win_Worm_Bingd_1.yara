rule Win_Worm_Bingd_1
{
strings:
	$a0 = { 506f6c69636965735c4578706c6f7265725c4e6f52756e222c312c225245475f44574f524422 }

condition:
	$a0
}

        
