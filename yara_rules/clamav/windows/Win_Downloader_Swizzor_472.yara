rule Win_Downloader_Swizzor_472
{
strings:
	$a0 = { 0cea70da6bf5ddae46708622fed8f604aa1ebd2953116c3eed0b1a5930e556374825b5c6efdecb0e0dbee99d02457fdeb861bbcd7cc6a4b3c19d9d6ac46357085165d2ad9d31ecfacd5979621d8cb4d0f32e8a85b1c7fa40eadb }

condition:
	$a0
}

        
