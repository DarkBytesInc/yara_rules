rule Win_Downloader_1238_1
{
strings:
	$a0 = { fdffff630080e2a966c78542fdffff5c00b5db80e53166c785ecfcffff660080c15266c785eafcffff690080f65780f58c66c785bcfdffff740066c78524fcffff3d0080cd0066c78580fcffff280066c785d8fcffff2000b52e66c785fefeffff620080e1b180c62366c785f2fe }

condition:
	$a0
}

        
