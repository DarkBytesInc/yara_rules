rule Win_Spyware_Banker_398
{
strings:
	$a0 = { 80f1a63a795bc5786eb2025b933f237223d0ada3bc97d6b971e776405ca37766b3b6464046c9ded944d42c77d5bf0fd95b351420245ee1ceff6a15ba72fa83a0ec77c05c2e704b55e84d82af0afb45bff022ede0da64f9a563a15d1b8d1f9d70b94d38647c0988a012bed902463190fd9d7380d3ac00fd6777d929788f0a3d196d9f543cb1c1a90a7b214246d98cbacbb3335f503db4 }

condition:
	$a0
}

        