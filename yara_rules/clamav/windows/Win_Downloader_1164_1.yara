rule Win_Downloader_1164_1
{
strings:
	$a0 = { 14f020ff20ff58eed6173db952c209e1efb47164e94890ed01f3bbc95c963e5801c9e94eb6d7ffb57802414c11affa44fb6cfde0eea63abcb5ff0bb33546d441b661a526c0ed6c9da5f8c271bf58ec20c391c1e2954c16b15efba08d }

condition:
	$a0
}

        
