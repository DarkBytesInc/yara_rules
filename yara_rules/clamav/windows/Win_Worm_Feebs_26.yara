rule Win_Worm_Feebs_26
{
strings:
	$a0 = { 30c117717c8c2d03d7677809000d78a90b2e044e123ff8cdb4dd31dc89786c44d832fa1e85f8927ec690c0f3096bee75aa4df74c9091712c8cdbc3ae9ef7856db3b1f58a70c3810db8cf565c17e92cfde34cc82b8032a71deefef24f944abbf7 }

condition:
	$a0
}

        
