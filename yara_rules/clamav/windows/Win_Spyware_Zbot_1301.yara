rule Win_Spyware_Zbot_1301
{
strings:
	$a0 = { 5589e581ec9401000052535057565355e8ea00000083c404b89f3340004050bf30b5f0ff81c7004b0f00578d9570feffffb9e79cb52081c1a1508bdf5152e881ffffff8b8d7cfeffff83ecf0ba4000000052ba0020000081c20010000052516a00ff15907640008945f0c745fc000000008b9d78feffff85db8b7df076558d85 }

condition:
	$a0
}

        