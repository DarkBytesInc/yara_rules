rule Win_Trojan_Spambot_215
{
strings:
	$a0 = { 45a63f6f05ffffffff30e659b81efbcdcd4a44b850929e87e90c367b9732366bb61918d0fbc9ca4c947ffdffffc20deb35ba8f9d64a9116053b9bf3cd068958b7d73896f40fdeaffff2ffe1d1c5eefeafc621ffb5921900a78febac71188814897d24ecaaeff7ff4ffa8ed5a24f9 }

condition:
	$a0
}

        
