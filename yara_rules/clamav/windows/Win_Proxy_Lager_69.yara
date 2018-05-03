rule Win_Proxy_Lager_69
{
strings:
	$a0 = { cd0bf4367a6510fbe61f5faac66bf3b6c009fcc068f1ffaa28a36d29f0eeef4ec5262f10c8088416cd76ed2ac26e9ae91f4a9192bfb3eef1effeabf7c011187db99e7404af8b }

condition:
	$a0
}

        
