rule Win_Trojan_Agent_35125
{
strings:
	$a0 = { bb4647704954bf8920422828096de7b5fc06b0954bc49f63e773aa58b4b6abe2e8f25f60dac5e6a4e3158ca3f03bf4c96c46d1cbedbdd4544f5375b801f1b326fc7757f9ecc59ee8459ac8d9c4c393a2 }

condition:
	$a0
}

        
