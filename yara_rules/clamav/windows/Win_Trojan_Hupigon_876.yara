rule Win_Trojan_Hupigon_876
{
strings:
	$a0 = { 640f1c2c93629b2bf545b11295204193d9cef50b736ed35b432a2c63f067e94994c136ad97069cbfaa68facdbafbe2179a8ef48ebcdeedc1bc4b674329e8620cae8734573590b489e1dbe52295a3b860dcad5f2c93d99cc861519a77b30fa9 }

condition:
	$a0
}

        
