rule Win_Trojan_NBSpy_1
{
strings:
	$a0 = { d567aaaf54dfa9ceaac2d5fdd483d497abaf565fab4e5167a8f3d5e3d593d537ababd4b5eab9eac5ea3bd577a9ef533fa47e54fd84fa59f58bea7dea37d4dfab4335519a019a4b34433523341a8d49334d53a939a8795b73a9ee6edd5f74d7e8 }

condition:
	$a0
}

        
