rule Win_Trojan_JS_293
{
strings:
	$a0 = { 3c212d2d68705f64[0-16]76632532326a7676722f6773776b743f7067647067716a2532 }

condition:
	$a0
}

        
