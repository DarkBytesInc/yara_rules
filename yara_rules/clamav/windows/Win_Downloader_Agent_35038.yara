rule Win_Downloader_Agent_35038
{
strings:
	$a0 = { 7647e7a18f06e1abe5b5a80b8d06b7ecdf639981e135cad2cc61b9d0b7bb9a84e56698d5d6d1dbb5e1350aa2b86ba5dad6698e81e131d7dfbe6d8e81e131d3c3a2718e81e131cfc7a6758e81e131cbcbaa798e81e131c7cfae7d8e81e131 }

condition:
	$a0
}

        
