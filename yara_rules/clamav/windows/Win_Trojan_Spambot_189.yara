rule Win_Trojan_Spambot_189
{
strings:
	$a0 = { 2f9ed941b69445c5cd6f0e5b0c3d0d36fcf662c0ff0f85704733c165852e4a9c72a57f7e0dff1fe0da7566e184ddd39ddd7c9a030e7fd2ffffffff2d3b546367addaec8ad96758569e8b9a80d37d44e39007064422963311fbf663ffffffff71a42e1128b65c40c8858ea9ed8bed }

condition:
	$a0
}

        
