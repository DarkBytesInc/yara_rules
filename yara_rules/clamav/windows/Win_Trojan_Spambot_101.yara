rule Win_Trojan_Spambot_101
{
strings:
	$a0 = { 343049b96922b7f564ca0d476b48d84b4e8f97ee408bffffffef3a7e9dbfc3c6ae6c2b2169ba09d77bebe90b15a80dd6f6f87fa18e89db0401ffffcbbd6e7f312cd31ff907237bfa3ae78cffffff7fab2ca1339345c5372aafa1a16f434b79e5509fec7a5013093601408cf2647f }

condition:
	$a0
}

        
