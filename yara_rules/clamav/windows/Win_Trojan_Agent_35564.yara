rule Win_Trojan_Agent_35564
{
strings:
	$a0 = { d1d6ccc8c8c89d412d4b24c4a843bdc04d3ec74c51c8c8c8434ec0ccc8c8418d3080418d3c8888418d3488414ec0ccc8c8a3b530d84574f6c4ccc8c8a39d3cd8455cdec4ccc8c89e411e71d8c8c8c83b6c96a3b530d84574f6c4ccc8c8438d3c }

condition:
	$a0
}

        
