rule Win_Trojan_Hupigon_787
{
strings:
	$a0 = { 3a6dc7c11711f4b22fb50f06b4a258be0a63284ff11a4533e303b9d7444932f10c51c89b40a3ad05e46e20e90bff0608bb0666cf40c03afc6adb2e9b0a9bc77f64aa2e58c8c8b6b165c35b2d3e1c8f5648e6905ce0db81a67127cbf63c26b8 }

condition:
	$a0
}

        
