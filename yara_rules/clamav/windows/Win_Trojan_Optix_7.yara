rule Win_Trojan_Optix_7
{
strings:
	$a0 = { 1cb5c3a9a23cd52a40740ea5274e666195ef8914ecdd68f6d0bc655358646e3735772baa0423b9f8a9b97f21668e5145a4d935ad38cf6ce7fa3303c55285e9ae1c882720e61faa0b2658a342cd6daf23deaca5bbb489 }

condition:
	$a0
}

        
