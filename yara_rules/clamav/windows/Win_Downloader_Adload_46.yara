rule Win_Downloader_Adload_46
{
strings:
	$a0 = { 6772f251ba2293b9fb02fa4c3aeca38260ccf4664dd6f04a4dc74486a5ea53ff3f7163a8ccadab2813408c576fa958ca1ba640a4fded7875a22764d61583a22aff9d5f508b52d13f85302047d7c5553a182d527fb989158a9d36a756a4dde9ff }

condition:
	$a0
}

        
