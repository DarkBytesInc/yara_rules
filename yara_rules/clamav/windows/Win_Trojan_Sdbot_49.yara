rule Win_Trojan_Sdbot_49
{
strings:
	$a0 = { c469ec0b9ba4d9b140d98ffb0ffd6b83b11da7d8f491ecb64eaea40ab821a314f5b9d92e8827a9c62969a67391e555bfb8fd9cafa4dee7c63c456e013e88d28ae8aab1e1d9c8eae672f44daacb2d401cb9ffe638b422bfed6f64c67061a5e60b2083a07b8a0ef9e5ba5544678167702d0713e13a495508d4 }

condition:
	$a0
}

        
