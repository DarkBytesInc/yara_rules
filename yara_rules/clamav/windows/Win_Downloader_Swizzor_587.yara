rule Win_Downloader_Swizzor_587
{
strings:
	$a0 = { fe37fc2ccff1e1ee051fb72e82199d88c0d940a3fb6b16f33b1490f024aec3001fff76d5720b86113669b4aae9c0c421eededee51ed33ca4e261af071666ea86c0f6ea23b77f0ee2d3fc5907d7c5d0cf1c1a02a85a5ac71f95331b687f4d304e170c9e33f093ea4e1a }

condition:
	$a0
}

        
