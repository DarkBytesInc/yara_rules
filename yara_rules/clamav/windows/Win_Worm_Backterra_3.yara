rule Win_Worm_Backterra_3
{
strings:
	$a0 = { 6520697320467574696c652e00656e2000000000ffcc31000159b27e7dba29614ba2672c113a0946265aa9f45047333d448b9b1b76be2664e93a4fad339966cf11b70c00aa0060d393000000000000000000000000000000000000000000000000000000000000000000000000830300005b03000000070066726d4c6f6164000d011500437261636b20627920537570 }

condition:
	$a0
}

        