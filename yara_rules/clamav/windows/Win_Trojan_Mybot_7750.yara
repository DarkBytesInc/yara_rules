rule Win_Trojan_Mybot_7750
{
strings:
	$a0 = { 6f8b0bde8c99de5a2affe24dd5853acdf785977b0a4b23edd010f8ba1778de4715ee72e7e30c2ed438dd427b65ff7996642b37b5afa0a7aa3e39c2818fa208df4bbf5fa06c77315ad2654db9182065e06a8ffa5dcb390fc6e95fd79b6de9b9b3f65d65989142 }

condition:
	$a0
}

        
