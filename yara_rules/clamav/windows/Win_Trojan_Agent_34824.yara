rule Win_Trojan_Agent_34824
{
strings:
	$a0 = { a3e9c26b966690cf1134aecec2580f25b64f341f71b7cd9d072080c9fcee26b6db76fc1bf9392de0fd42180cc3ebdd5b41aa8351bfeec85cdbfc542df2095ebd34cb428951613b31d1d8ec2c350aad84e18cdeac5676cb3f005f9794997d53acc0ce4815eba664b4c118018fe45f5ac8de59e3486be6dd95 }

condition:
	$a0
}

        
