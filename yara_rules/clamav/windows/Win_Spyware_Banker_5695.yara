rule Win_Spyware_Banker_5695
{
strings:
	$a0 = { 03c10a831a10e6c8181420574b7210d5499b87e49813a049a760e8e48281723d5c72ef7da8396b42e18562ab05fbf107d6ddc96fbcafdc14e4a329e4a4f71ae2e9a2250f2e6ebc46295cbe8acdcff0c81dd0a1df4efce90317be }

condition:
	$a0
}

        
