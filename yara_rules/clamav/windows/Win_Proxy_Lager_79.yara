rule Win_Proxy_Lager_79
{
strings:
	$a0 = { e4fe73b9d355f277da0f7efcf90baedc4e654a11d21f0540f26ba95cf409a62a5cf1a5401ca337c3c4eeb5a4f12675fafc08defcf976b7c0f66ec0032b4acb788bb3b41bdbfe }

condition:
	$a0
}

        
