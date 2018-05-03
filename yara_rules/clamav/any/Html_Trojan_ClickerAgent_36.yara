rule Html_Trojan_ClickerAgent_36
{
strings:
	$a0 = { 6d7cbfbece124e32a7e7c7f457a32a83784db20e33bd5b02113fe6cb275032c8853aa0fce4a1309104faadeec1cef40ac185882b58ec28a9e6cb7dbb77ffa8be75377d47965af033d819d7a37e1353901e78310085cc29b54f4f18007cb8ba0d }

condition:
	$a0
}

        
